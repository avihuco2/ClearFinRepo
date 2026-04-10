// @clearfin/auth-service — Session Manager
// Issues signed session JWTs and refresh tokens with token family tracking.
// Encrypts session data at rest using AES-256 (simulating KMS_Key encryption).

import { randomUUID, createHmac, createCipheriv, randomBytes } from "node:crypto";
import {
  type Result,
  type SessionTokenPayload,
  type RefreshTokenRecord,
  ok,
  err,
} from "@clearfin/shared";
import type { Logger } from "@clearfin/shared";

// ── Types ────────────────────────────────────────────────────────────

export interface SessionTokens {
  jwt: string;
  refreshTokenId: string;
}

export interface SessionError {
  code:
    | "SIGNING_FAILED"
    | "STORE_FAILED"
    | "INVALID_CLAIMS"
    | "INVALID_REFRESH_TOKEN"
    | "TOKEN_EXPIRED"
    | "TOKEN_REPLAY_DETECTED";
  message: string;
}

export interface SessionManagerConfig {
  /** HMAC-SHA256 secret key for JWT signing (min 32 bytes recommended). */
  signingSecret: string;
  /** AES-256 key for encrypting session data at rest (must be 32 bytes). */
  encryptionKey: Buffer;
}

/** Represents an encrypted record stored in the Session_Store. */
export interface EncryptedSessionRecord {
  iv: string;       // hex-encoded initialization vector
  ciphertext: string; // hex-encoded encrypted data
  tag: string;       // hex-encoded auth tag (AES-256-GCM)
}

// ── Constants ────────────────────────────────────────────────────────

const SESSION_JWT_LIFETIME_SECONDS = 900;       // 15 minutes
const REFRESH_TOKEN_LIFETIME_SECONDS = 28800;   // 8 hours

// ── Helpers ──────────────────────────────────────────────────────────

/** Base64url-encode a buffer or string. */
function base64urlEncode(input: Buffer | string): string {
  const buf = typeof input === "string" ? Buffer.from(input) : input;
  return buf.toString("base64url");
}

/** Build a signed JWT using HMAC-SHA256. */
function signJwt(payload: SessionTokenPayload, secret: string): string {
  const header = { alg: "HS256", typ: "JWT" };
  const encodedHeader = base64urlEncode(JSON.stringify(header));
  const encodedPayload = base64urlEncode(JSON.stringify(payload));
  const signingInput = `${encodedHeader}.${encodedPayload}`;
  const signature = createHmac("sha256", secret).update(signingInput).digest();
  return `${signingInput}.${base64urlEncode(signature)}`;
}

/** Encrypt data at rest using AES-256-GCM (simulating KMS_Key encryption). */
function encryptAes256Gcm(data: string, key: Buffer): EncryptedSessionRecord {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  let ciphertext = cipher.update(data, "utf8", "hex");
  ciphertext += cipher.final("hex");
  const tag = cipher.getAuthTag();
  return {
    iv: iv.toString("hex"),
    ciphertext,
    tag: tag.toString("hex"),
  };
}

// ── SessionManager ───────────────────────────────────────────────────

export class SessionManager {
  private refreshTokenStore = new Map<string, RefreshTokenRecord>();
  private encryptedStore = new Map<string, EncryptedSessionRecord>();
  /** Maps tokenFamily → set of jtis for encrypted session cleanup. */
  private tokenFamilyJtis = new Map<string, Set<string>>();
  private readonly config: SessionManagerConfig;
  private readonly logger: Logger;

  constructor(config: SessionManagerConfig, logger: Logger) {
    this.config = config;
    this.logger = logger;
  }

  /**
   * Create a new session: sign a JWT and issue a refresh token.
   *
   * @param userClaims - Object with `sub` (user subject ID)
   * @param tenantId   - Tenant identifier to embed in the token
   * @param nowSeconds - Injectable current time in epoch seconds (for testing)
   */
  createSession(
    userClaims: { sub: string },
    tenantId: string,
    nowSeconds: number = Math.floor(Date.now() / 1000),
  ): Result<SessionTokens, SessionError> {
    if (!userClaims.sub || !tenantId) {
      return err({
        code: "INVALID_CLAIMS",
        message: "sub and tenantId are required",
      });
    }

    const jti = randomUUID();
    const tokenFamily = randomUUID();

    // Build JWT payload per Requirement 2.1, 2.6
    const payload: SessionTokenPayload = {
      sub: userClaims.sub,
      tenantId,
      iat: nowSeconds,
      exp: nowSeconds + SESSION_JWT_LIFETIME_SECONDS,
      jti,
      tokenFamily,
    };

    // Sign the JWT with HMAC-SHA256
    let jwt: string;
    try {
      jwt = signJwt(payload, this.config.signingSecret);
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Unknown signing error";
      this.logger.error("Failed to sign session JWT", { error: msg });
      return err({ code: "SIGNING_FAILED", message: msg });
    }

    // Create refresh token record (8-hour expiration, linked to token family)
    const refreshTokenId = randomUUID();
    const issuedAt = new Date(nowSeconds * 1000);
    const refreshToken: RefreshTokenRecord = {
      id: refreshTokenId,
      tokenFamily,
      userId: userClaims.sub,
      tenantId,
      issuedAt,
      expiresAt: new Date((nowSeconds + REFRESH_TOKEN_LIFETIME_SECONDS) * 1000),
      consumed: false,
      revokedAt: null,
    };

    // Store refresh token
    this.refreshTokenStore.set(refreshTokenId, refreshToken);

    // Encrypt session data at rest (Requirement 2.2)
    try {
      const sessionData = JSON.stringify({ payload, refreshTokenId });
      const encrypted = encryptAes256Gcm(sessionData, this.config.encryptionKey);
      this.encryptedStore.set(jti, encrypted);
      // Track jti → tokenFamily for cleanup during revocation
      if (!this.tokenFamilyJtis.has(tokenFamily)) {
        this.tokenFamilyJtis.set(tokenFamily, new Set());
      }
      this.tokenFamilyJtis.get(tokenFamily)!.add(jti);
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Unknown encryption error";
      this.logger.error("Failed to encrypt session data", { error: msg });
      return err({ code: "STORE_FAILED", message: msg });
    }

    this.logger.info("Session created", {
      sub: userClaims.sub,
      tenantId,
      jti,
      tokenFamily,
      refreshTokenId,
    });

    return ok({ jwt, refreshTokenId });
  }

  /**
   * Refresh a session: validate the refresh token, rotate it, and issue new tokens.
   *
   * - If the token is not found → INVALID_REFRESH_TOKEN
   * - If the token is expired → TOKEN_EXPIRED
   * - If the token was already consumed (replay attack) → revoke entire family, TOKEN_REPLAY_DETECTED (CRITICAL)
   * - If valid → mark consumed, issue new JWT + new refresh token with same tokenFamily
   *
   * @param refreshTokenId - The ID of the refresh token to consume
   * @param nowSeconds     - Injectable current time in epoch seconds (for testing)
   *
   * Requirements: 2.3, 2.4, 2.5
   */
  refreshSession(
    refreshTokenId: string,
    nowSeconds: number = Math.floor(Date.now() / 1000),
  ): Result<SessionTokens, SessionError> {
    const existing = this.refreshTokenStore.get(refreshTokenId);

    // Token not found
    if (!existing) {
      this.logger.warn("Refresh token not found", { refreshTokenId });
      return err({
        code: "INVALID_REFRESH_TOKEN",
        message: "Refresh token not found",
      });
    }

    // Token expired
    const expiresAtSeconds = Math.floor(existing.expiresAt.getTime() / 1000);
    if (nowSeconds >= expiresAtSeconds) {
      this.logger.warn("Refresh token expired", {
        refreshTokenId,
        tokenFamily: existing.tokenFamily,
        expiresAt: existing.expiresAt.toISOString(),
      });
      return err({
        code: "TOKEN_EXPIRED",
        message: "Refresh token has expired",
      });
    }

    // Replay attack: token was already consumed → revoke entire family
    if (existing.consumed) {
      const revokedIds = this.revokeTokenFamily(existing.tokenFamily, nowSeconds);
      this.logger.critical("Token replay detected — entire token family revoked", {
        refreshTokenId,
        tokenFamily: existing.tokenFamily,
        revokedTokenIds: revokedIds,
      });
      return err({
        code: "TOKEN_REPLAY_DETECTED",
        message: "Consumed refresh token reused; token family revoked",
      });
    }

    // Valid token: mark as consumed (Requirement 2.4)
    existing.consumed = true;

    // Issue new JWT + refresh token with the same tokenFamily
    const jti = randomUUID();
    const payload: SessionTokenPayload = {
      sub: existing.userId,
      tenantId: existing.tenantId,
      iat: nowSeconds,
      exp: nowSeconds + SESSION_JWT_LIFETIME_SECONDS,
      jti,
      tokenFamily: existing.tokenFamily,
    };

    let jwt: string;
    try {
      jwt = signJwt(payload, this.config.signingSecret);
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Unknown signing error";
      this.logger.error("Failed to sign session JWT during refresh", { error: msg });
      return err({ code: "SIGNING_FAILED", message: msg });
    }

    // Create new refresh token in the same family
    const newRefreshTokenId = randomUUID();
    const newRefreshToken: RefreshTokenRecord = {
      id: newRefreshTokenId,
      tokenFamily: existing.tokenFamily,
      userId: existing.userId,
      tenantId: existing.tenantId,
      issuedAt: new Date(nowSeconds * 1000),
      expiresAt: new Date((nowSeconds + REFRESH_TOKEN_LIFETIME_SECONDS) * 1000),
      consumed: false,
      revokedAt: null,
    };
    this.refreshTokenStore.set(newRefreshTokenId, newRefreshToken);

    // Encrypt session data at rest (Requirement 2.2)
    try {
      const sessionData = JSON.stringify({ payload, refreshTokenId: newRefreshTokenId });
      const encrypted = encryptAes256Gcm(sessionData, this.config.encryptionKey);
      this.encryptedStore.set(jti, encrypted);
      // Track jti → tokenFamily for cleanup during revocation
      if (!this.tokenFamilyJtis.has(existing.tokenFamily)) {
        this.tokenFamilyJtis.set(existing.tokenFamily, new Set());
      }
      this.tokenFamilyJtis.get(existing.tokenFamily)!.add(jti);
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Unknown encryption error";
      this.logger.error("Failed to encrypt session data during refresh", { error: msg });
      return err({ code: "STORE_FAILED", message: msg });
    }

    this.logger.info("Session refreshed", {
      sub: existing.userId,
      tenantId: existing.tenantId,
      tokenFamily: existing.tokenFamily,
      oldRefreshTokenId: refreshTokenId,
      newRefreshTokenId,
      jti,
    });

    return ok({ jwt, refreshTokenId: newRefreshTokenId });
  }

  /**
   * Revoke all refresh tokens in a token family.
   * Sets `revokedAt` on every token in the family.
   *
   * @returns Array of revoked token IDs
   */
  revokeTokenFamily(tokenFamily: string, nowSeconds: number = Math.floor(Date.now() / 1000)): string[] {
    const revokedIds: string[] = [];
    const revokedAt = new Date(nowSeconds * 1000);

    for (const [id, token] of this.refreshTokenStore) {
      if (token.tokenFamily === tokenFamily && token.revokedAt === null) {
        token.revokedAt = revokedAt;
        revokedIds.push(id);
      }
    }

    this.logger.warn("Token family revoked", {
      tokenFamily,
      revokedCount: revokedIds.length,
      revokedTokenIds: revokedIds,
    });

    return revokedIds;
  }

  /**
   * Revoke a session: invalidate the refresh token and its entire token family,
   * then remove encrypted session data from the store.
   *
   * @param refreshTokenId - The ID of the refresh token associated with the session
   * @param nowSeconds     - Injectable current time in epoch seconds (for testing)
   *
   * Requirements: 2.7 — invalidation within 1 second (trivially met for in-memory store)
   */
  revokeSession(
    refreshTokenId: string,
    nowSeconds: number = Math.floor(Date.now() / 1000),
  ): Result<void, SessionError> {
    const token = this.refreshTokenStore.get(refreshTokenId);

    if (!token) {
      this.logger.warn("Revoke session: refresh token not found", { refreshTokenId });
      return err({
        code: "INVALID_REFRESH_TOKEN",
        message: "Refresh token not found",
      });
    }

    // Revoke the entire token family (Requirement 2.7)
    const revokedIds = this.revokeTokenFamily(token.tokenFamily, nowSeconds);

    // Remove all encrypted session records associated with revoked tokens
    const jtis = this.tokenFamilyJtis.get(token.tokenFamily);
    if (jtis) {
      for (const jti of jtis) {
        this.encryptedStore.delete(jti);
      }
      this.tokenFamilyJtis.delete(token.tokenFamily);
    }

    this.logger.info("Session revoked", {
      refreshTokenId,
      tokenFamily: token.tokenFamily,
      revokedTokenIds: revokedIds,
    });

    return ok(undefined);
  }

  // ── Accessors for testing / future tasks ─────────────────────────

  /** Retrieve a refresh token record by ID. */
  getRefreshToken(id: string): RefreshTokenRecord | undefined {
    return this.refreshTokenStore.get(id);
  }

  /** Retrieve an encrypted session record by jti. */
  getEncryptedSession(jti: string): EncryptedSessionRecord | undefined {
    return this.encryptedStore.get(jti);
  }

  /** Number of active refresh tokens (useful for testing). */
  get refreshTokenCount(): number {
    return this.refreshTokenStore.size;
  }
}
