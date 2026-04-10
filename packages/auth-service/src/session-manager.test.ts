// @clearfin/auth-service — Unit tests for SessionManager.createSession
import { describe, it, expect, beforeEach } from "vitest";
import { randomBytes } from "node:crypto";
import { createLogger } from "@clearfin/shared";
import { SessionManager } from "./session-manager.js";
import type { SessionManagerConfig } from "./session-manager.js";

// ── Helpers ──────────────────────────────────────────────────────────

function silentLogger() {
  return createLogger("test", "test-corr-id", {}, () => {});
}

function makeConfig(overrides?: Partial<SessionManagerConfig>): SessionManagerConfig {
  return {
    signingSecret: "test-secret-key-at-least-32-bytes-long!!",
    encryptionKey: randomBytes(32),
    ...overrides,
  };
}

/** Decode a JWT without verification, returning the payload. */
function decodeJwtPayload(jwt: string): Record<string, unknown> {
  const parts = jwt.split(".");
  expect(parts).toHaveLength(3);
  return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
}

// ── Tests ────────────────────────────────────────────────────────────

describe("SessionManager.createSession", () => {
  let manager: SessionManager;

  beforeEach(() => {
    manager = new SessionManager(makeConfig(), silentLogger());
  });

  it("returns ok with jwt and refreshTokenId", () => {
    const result = manager.createSession({ sub: "user-123" }, "tenant-abc");
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.jwt).toBeTypeOf("string");
    expect(result.value.refreshTokenId).toBeTypeOf("string");
  });

  it("JWT contains correct payload fields (sub, tenantId, iat, exp, jti, tokenFamily)", () => {
    const now = 1700000000;
    const result = manager.createSession({ sub: "user-42" }, "tenant-xyz", now);
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const payload = decodeJwtPayload(result.value.jwt);
    expect(payload.sub).toBe("user-42");
    expect(payload.tenantId).toBe("tenant-xyz");
    expect(payload.iat).toBe(now);
    expect(payload.exp).toBe(now + 900); // 15 minutes
    expect(payload.jti).toBeTypeOf("string");
    expect(payload.tokenFamily).toBeTypeOf("string");
  });

  it("exp equals iat + 900 seconds (15 minutes)", () => {
    const now = 1710000000;
    const result = manager.createSession({ sub: "u1" }, "t1", now);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const payload = decodeJwtPayload(result.value.jwt);
    expect(payload.exp).toBe(1710000000 + 900);
  });

  it("refresh token has 8-hour expiration linked to token family", () => {
    const now = 1700000000;
    const result = manager.createSession({ sub: "user-1" }, "tenant-1", now);
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const rt = manager.getRefreshToken(result.value.refreshTokenId);
    expect(rt).toBeDefined();
    if (!rt) return;

    expect(rt.userId).toBe("user-1");
    expect(rt.tenantId).toBe("tenant-1");
    expect(rt.consumed).toBe(false);
    expect(rt.revokedAt).toBeNull();
    expect(rt.issuedAt.getTime()).toBe(now * 1000);
    expect(rt.expiresAt.getTime()).toBe((now + 28800) * 1000); // 8 hours

    // Token family should match the JWT's tokenFamily
    const payload = decodeJwtPayload(result.value.jwt);
    expect(rt.tokenFamily).toBe(payload.tokenFamily);
  });

  it("stores encrypted session data at rest (AES-256-GCM)", () => {
    const now = 1700000000;
    const result = manager.createSession({ sub: "u1" }, "t1", now);
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const payload = decodeJwtPayload(result.value.jwt);
    const encrypted = manager.getEncryptedSession(payload.jti as string);
    expect(encrypted).toBeDefined();
    if (!encrypted) return;

    // Verify it has the expected AES-256-GCM structure
    expect(encrypted.iv).toBeTypeOf("string");
    expect(encrypted.ciphertext).toBeTypeOf("string");
    expect(encrypted.tag).toBeTypeOf("string");
    // IV should be 12 bytes = 24 hex chars
    expect(encrypted.iv).toHaveLength(24);
    // Ciphertext should not be empty
    expect(encrypted.ciphertext.length).toBeGreaterThan(0);
  });

  it("JWT has valid HMAC-SHA256 structure (3 base64url parts)", () => {
    const result = manager.createSession({ sub: "u" }, "t");
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const parts = result.value.jwt.split(".");
    expect(parts).toHaveLength(3);

    // Header should decode to { alg: "HS256", typ: "JWT" }
    const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    expect(header.alg).toBe("HS256");
    expect(header.typ).toBe("JWT");
  });

  it("each session gets unique jti and tokenFamily", () => {
    const r1 = manager.createSession({ sub: "u" }, "t");
    const r2 = manager.createSession({ sub: "u" }, "t");
    expect(r1.ok && r2.ok).toBe(true);
    if (!r1.ok || !r2.ok) return;

    const p1 = decodeJwtPayload(r1.value.jwt);
    const p2 = decodeJwtPayload(r2.value.jwt);
    expect(p1.jti).not.toBe(p2.jti);
    expect(p1.tokenFamily).not.toBe(p2.tokenFamily);
  });

  it("rejects empty sub", () => {
    const result = manager.createSession({ sub: "" }, "tenant-1");
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe("INVALID_CLAIMS");
  });

  it("rejects empty tenantId", () => {
    const result = manager.createSession({ sub: "user-1" }, "");
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe("INVALID_CLAIMS");
  });

  it("increments refresh token count on each session creation", () => {
    expect(manager.refreshTokenCount).toBe(0);
    manager.createSession({ sub: "u1" }, "t1");
    expect(manager.refreshTokenCount).toBe(1);
    manager.createSession({ sub: "u2" }, "t2");
    expect(manager.refreshTokenCount).toBe(2);
  });
});

// ── Tests for refreshSession ─────────────────────────────────────────

describe("SessionManager.refreshSession", () => {
  let manager: SessionManager;
  const now = 1700000000;

  beforeEach(() => {
    manager = new SessionManager(makeConfig(), silentLogger());
  });

  it("returns INVALID_REFRESH_TOKEN for unknown token ID", () => {
    const result = manager.refreshSession("nonexistent-id", now);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe("INVALID_REFRESH_TOKEN");
  });

  it("returns TOKEN_EXPIRED when refresh token has expired", () => {
    const createResult = manager.createSession({ sub: "u1" }, "t1", now);
    expect(createResult.ok).toBe(true);
    if (!createResult.ok) return;

    // Advance time past the 8-hour expiration
    const expiredTime = now + 28800; // exactly at expiration boundary
    const result = manager.refreshSession(createResult.value.refreshTokenId, expiredTime);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe("TOKEN_EXPIRED");
  });

  it("succeeds with a valid, unconsumed refresh token", () => {
    const createResult = manager.createSession({ sub: "u1" }, "t1", now);
    expect(createResult.ok).toBe(true);
    if (!createResult.ok) return;

    const refreshResult = manager.refreshSession(
      createResult.value.refreshTokenId,
      now + 60,
    );
    expect(refreshResult.ok).toBe(true);
    if (!refreshResult.ok) return;

    expect(refreshResult.value.jwt).toBeTypeOf("string");
    expect(refreshResult.value.refreshTokenId).toBeTypeOf("string");
    // New refresh token ID should differ from the old one
    expect(refreshResult.value.refreshTokenId).not.toBe(createResult.value.refreshTokenId);
  });

  it("marks the original refresh token as consumed after refresh", () => {
    const createResult = manager.createSession({ sub: "u1" }, "t1", now);
    expect(createResult.ok).toBe(true);
    if (!createResult.ok) return;

    const oldId = createResult.value.refreshTokenId;
    manager.refreshSession(oldId, now + 60);

    const oldToken = manager.getRefreshToken(oldId);
    expect(oldToken).toBeDefined();
    expect(oldToken!.consumed).toBe(true);
  });

  it("new refresh token shares the same tokenFamily as the original", () => {
    const createResult = manager.createSession({ sub: "u1" }, "t1", now);
    expect(createResult.ok).toBe(true);
    if (!createResult.ok) return;

    const originalRt = manager.getRefreshToken(createResult.value.refreshTokenId);
    expect(originalRt).toBeDefined();

    const refreshResult = manager.refreshSession(
      createResult.value.refreshTokenId,
      now + 60,
    );
    expect(refreshResult.ok).toBe(true);
    if (!refreshResult.ok) return;

    const newRt = manager.getRefreshToken(refreshResult.value.refreshTokenId);
    expect(newRt).toBeDefined();
    expect(newRt!.tokenFamily).toBe(originalRt!.tokenFamily);
    expect(newRt!.consumed).toBe(false);
  });

  it("new JWT contains correct sub, tenantId, iat, exp from the refreshed session", () => {
    const createResult = manager.createSession({ sub: "u1" }, "t1", now);
    expect(createResult.ok).toBe(true);
    if (!createResult.ok) return;

    const refreshTime = now + 300;
    const refreshResult = manager.refreshSession(
      createResult.value.refreshTokenId,
      refreshTime,
    );
    expect(refreshResult.ok).toBe(true);
    if (!refreshResult.ok) return;

    const payload = decodeJwtPayload(refreshResult.value.jwt);
    expect(payload.sub).toBe("u1");
    expect(payload.tenantId).toBe("t1");
    expect(payload.iat).toBe(refreshTime);
    expect(payload.exp).toBe(refreshTime + 900);
  });

  it("detects replay: reusing a consumed token revokes entire family", () => {
    const createResult = manager.createSession({ sub: "u1" }, "t1", now);
    expect(createResult.ok).toBe(true);
    if (!createResult.ok) return;

    const oldId = createResult.value.refreshTokenId;

    // First refresh — should succeed
    const r1 = manager.refreshSession(oldId, now + 60);
    expect(r1.ok).toBe(true);
    if (!r1.ok) return;

    // Replay the consumed token — should detect replay
    const r2 = manager.refreshSession(oldId, now + 120);
    expect(r2.ok).toBe(false);
    if (r2.ok) return;
    expect(r2.error.code).toBe("TOKEN_REPLAY_DETECTED");

    // The new token from r1 should also be revoked (entire family)
    const newRt = manager.getRefreshToken(r1.value.refreshTokenId);
    expect(newRt).toBeDefined();
    expect(newRt!.revokedAt).not.toBeNull();
  });

  it("revokes all tokens in a 3-rotation chain on replay", () => {
    const createResult = manager.createSession({ sub: "u1" }, "t1", now);
    expect(createResult.ok).toBe(true);
    if (!createResult.ok) return;

    const id0 = createResult.value.refreshTokenId;

    // Rotation 1
    const r1 = manager.refreshSession(id0, now + 60);
    expect(r1.ok).toBe(true);
    if (!r1.ok) return;
    const id1 = r1.value.refreshTokenId;

    // Rotation 2
    const r2 = manager.refreshSession(id1, now + 120);
    expect(r2.ok).toBe(true);
    if (!r2.ok) return;
    const id2 = r2.value.refreshTokenId;

    // Rotation 3
    const r3 = manager.refreshSession(id2, now + 180);
    expect(r3.ok).toBe(true);
    if (!r3.ok) return;
    const id3 = r3.value.refreshTokenId;

    // Replay token from rotation 1 (id1 was consumed)
    const replay = manager.refreshSession(id1, now + 240);
    expect(replay.ok).toBe(false);
    if (replay.ok) return;
    expect(replay.error.code).toBe("TOKEN_REPLAY_DETECTED");

    // ALL tokens in the family should be revoked
    for (const id of [id0, id1, id2, id3]) {
      const token = manager.getRefreshToken(id);
      expect(token).toBeDefined();
      expect(token!.revokedAt).not.toBeNull();
    }
  });

  it("refresh token just before expiration succeeds", () => {
    const createResult = manager.createSession({ sub: "u1" }, "t1", now);
    expect(createResult.ok).toBe(true);
    if (!createResult.ok) return;

    // 1 second before expiration
    const almostExpired = now + 28800 - 1;
    const result = manager.refreshSession(
      createResult.value.refreshTokenId,
      almostExpired,
    );
    expect(result.ok).toBe(true);
  });
});

// ── Tests for revokeTokenFamily ──────────────────────────────────────

describe("SessionManager.revokeTokenFamily", () => {
  let manager: SessionManager;
  const now = 1700000000;

  beforeEach(() => {
    manager = new SessionManager(makeConfig(), silentLogger());
  });

  it("revokes all tokens in a family", () => {
    const createResult = manager.createSession({ sub: "u1" }, "t1", now);
    expect(createResult.ok).toBe(true);
    if (!createResult.ok) return;

    const rt = manager.getRefreshToken(createResult.value.refreshTokenId);
    expect(rt).toBeDefined();

    const revokedIds = manager.revokeTokenFamily(rt!.tokenFamily, now + 10);
    expect(revokedIds).toContain(createResult.value.refreshTokenId);

    const afterRevoke = manager.getRefreshToken(createResult.value.refreshTokenId);
    expect(afterRevoke!.revokedAt).not.toBeNull();
  });

  it("does not revoke tokens from a different family", () => {
    const s1 = manager.createSession({ sub: "u1" }, "t1", now);
    const s2 = manager.createSession({ sub: "u2" }, "t2", now);
    expect(s1.ok && s2.ok).toBe(true);
    if (!s1.ok || !s2.ok) return;

    const rt1 = manager.getRefreshToken(s1.value.refreshTokenId)!;
    manager.revokeTokenFamily(rt1.tokenFamily, now + 10);

    // s2's token should be unaffected
    const rt2 = manager.getRefreshToken(s2.value.refreshTokenId)!;
    expect(rt2.revokedAt).toBeNull();
  });

  it("returns empty array for unknown family", () => {
    const revokedIds = manager.revokeTokenFamily("nonexistent-family", now);
    expect(revokedIds).toHaveLength(0);
  });
});

// ── Tests for revokeSession ──────────────────────────────────────────

describe("SessionManager.revokeSession", () => {
  let manager: SessionManager;
  const now = 1700000000;

  beforeEach(() => {
    manager = new SessionManager(makeConfig(), silentLogger());
  });

  it("returns INVALID_REFRESH_TOKEN for unknown token ID", () => {
    const result = manager.revokeSession("nonexistent-id", now);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe("INVALID_REFRESH_TOKEN");
  });

  it("returns ok and revokes the token family on valid refresh token", () => {
    const createResult = manager.createSession({ sub: "u1" }, "t1", now);
    expect(createResult.ok).toBe(true);
    if (!createResult.ok) return;

    const result = manager.revokeSession(createResult.value.refreshTokenId, now + 10);
    expect(result.ok).toBe(true);

    // Refresh token should be revoked
    const rt = manager.getRefreshToken(createResult.value.refreshTokenId);
    expect(rt).toBeDefined();
    expect(rt!.revokedAt).not.toBeNull();
  });

  it("removes encrypted session data from the store", () => {
    const createResult = manager.createSession({ sub: "u1" }, "t1", now);
    expect(createResult.ok).toBe(true);
    if (!createResult.ok) return;

    const payload = decodeJwtPayload(createResult.value.jwt);
    const jti = payload.jti as string;

    // Encrypted session should exist before revocation
    expect(manager.getEncryptedSession(jti)).toBeDefined();

    manager.revokeSession(createResult.value.refreshTokenId, now + 10);

    // Encrypted session should be removed after revocation
    expect(manager.getEncryptedSession(jti)).toBeUndefined();
  });

  it("revokes all tokens in the family after multiple rotations", () => {
    const createResult = manager.createSession({ sub: "u1" }, "t1", now);
    expect(createResult.ok).toBe(true);
    if (!createResult.ok) return;

    const id0 = createResult.value.refreshTokenId;

    // Rotate twice
    const r1 = manager.refreshSession(id0, now + 60);
    expect(r1.ok).toBe(true);
    if (!r1.ok) return;
    const id1 = r1.value.refreshTokenId;

    const r2 = manager.refreshSession(id1, now + 120);
    expect(r2.ok).toBe(true);
    if (!r2.ok) return;
    const id2 = r2.value.refreshTokenId;

    // Revoke using the latest refresh token
    const result = manager.revokeSession(id2, now + 180);
    expect(result.ok).toBe(true);

    // All tokens in the family should be revoked
    for (const id of [id0, id1, id2]) {
      const token = manager.getRefreshToken(id);
      expect(token).toBeDefined();
      expect(token!.revokedAt).not.toBeNull();
    }
  });

  it("does not affect sessions from a different token family", () => {
    const s1 = manager.createSession({ sub: "u1" }, "t1", now);
    const s2 = manager.createSession({ sub: "u2" }, "t2", now);
    expect(s1.ok && s2.ok).toBe(true);
    if (!s1.ok || !s2.ok) return;

    const p2 = decodeJwtPayload(s2.value.jwt);
    const jti2 = p2.jti as string;

    // Revoke session 1
    manager.revokeSession(s1.value.refreshTokenId, now + 10);

    // Session 2's refresh token should be unaffected
    const rt2 = manager.getRefreshToken(s2.value.refreshTokenId);
    expect(rt2).toBeDefined();
    expect(rt2!.revokedAt).toBeNull();

    // Session 2's encrypted data should still exist
    expect(manager.getEncryptedSession(jti2)).toBeDefined();
  });

  it("completes within 1 second (in-memory SLA)", () => {
    const createResult = manager.createSession({ sub: "u1" }, "t1", now);
    expect(createResult.ok).toBe(true);
    if (!createResult.ok) return;

    const start = performance.now();
    const result = manager.revokeSession(createResult.value.refreshTokenId, now + 10);
    const elapsed = performance.now() - start;

    expect(result.ok).toBe(true);
    expect(elapsed).toBeLessThan(1000); // Must complete within 1 second
  });
});
