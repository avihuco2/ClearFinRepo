// @clearfin/auth-service — Google id_token validation
// Validates JWT signature against Google JWKS, verifies aud, iss, and exp claims.
// Uses dependency injection for the JWKS fetcher to enable testing.

import { type Result, ok, err } from "@clearfin/shared";
import type { Logger } from "@clearfin/shared";

// ── Types ────────────────────────────────────────────────────────────

export interface UserClaims {
  sub: string;
  email: string;
  name: string;
  picture?: string;
  emailVerified?: boolean;
}

export interface IdTokenError {
  code:
    | "INVALID_SIGNATURE"
    | "INVALID_AUD"
    | "INVALID_ISS"
    | "TOKEN_EXPIRED"
    | "MALFORMED_TOKEN"
    | "MISSING_CLAIMS"
    | "JWKS_FETCH_FAILED";
  httpStatus: 401;
  message: string;
}

/** A single JSON Web Key from a JWKS endpoint. */
export interface JWK {
  kty: string;
  kid: string;
  n: string;
  e: string;
  alg?: string;
  use?: string;
}

/** Interface for fetching Google's JWKS — injectable for testing. */
export interface JwksFetcher {
  fetchKeys(): Promise<JWK[]>;
}

// ── Helpers ──────────────────────────────────────────────────────────

/** Base64url-decode to a Buffer. */
function base64urlDecode(input: string): Buffer {
  // Replace URL-safe chars and add padding
  const base64 = input.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  return Buffer.from(padded, "base64");
}

/** Decode a JWT into its three parts without verifying. */
function decodeJwt(token: string): {
  header: { alg: string; kid?: string; typ?: string };
  payload: Record<string, unknown>;
  signatureBytes: Buffer;
  signedContent: string;
} | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;

  try {
    const header = JSON.parse(base64urlDecode(parts[0]).toString("utf8"));
    const payload = JSON.parse(base64urlDecode(parts[1]).toString("utf8"));
    const signatureBytes = base64urlDecode(parts[2]);
    const signedContent = `${parts[0]}.${parts[1]}`;
    return { header, payload, signatureBytes, signedContent };
  } catch {
    return null;
  }
}

/** Convert a JWK RSA public key to a Node.js KeyObject for verification. */
async function jwkToPublicKey(jwk: JWK): Promise<import("node:crypto").KeyObject> {
  const { createPublicKey } = await import("node:crypto");
  return createPublicKey({
    key: {
      kty: jwk.kty,
      n: jwk.n,
      e: jwk.e,
    },
    format: "jwk",
  });
}

/** Verify an RSA-SHA256 signature. */
async function verifySignature(
  signedContent: string,
  signatureBytes: Buffer,
  publicKey: import("node:crypto").KeyObject,
): Promise<boolean> {
  const { createVerify } = await import("node:crypto");
  const verifier = createVerify("RSA-SHA256");
  verifier.update(signedContent);
  return verifier.verify(publicKey, signatureBytes);
}

// ── Validator ────────────────────────────────────────────────────────

/**
 * Validate a Google id_token.
 *
 * 1. Decode the JWT (header, payload, signature)
 * 2. Verify signature against Google JWKS (matched by `kid`)
 * 3. Verify `aud` matches expectedAud
 * 4. Verify `iss` matches expectedIss
 * 5. Verify token is not expired (`exp`)
 * 6. Extract and return UserClaims
 *
 * @param nowSeconds — injectable current-time for testing (defaults to Date.now()/1000)
 */
export async function validateIdToken(
  idToken: string,
  expectedAud: string,
  expectedIss: string,
  jwksFetcher: JwksFetcher,
  logger: Logger,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): Promise<Result<UserClaims, IdTokenError>> {
  // 1. Decode
  const decoded = decodeJwt(idToken);
  if (!decoded) {
    logger.warn("id_token validation failed: malformed token");
    return err({
      code: "MALFORMED_TOKEN",
      httpStatus: 401 as const,
      message: "id_token is not a valid JWT",
    });
  }

  const { header, payload, signatureBytes, signedContent } = decoded;

  // 2. Verify signature against JWKS
  let keys: JWK[];
  try {
    keys = await jwksFetcher.fetchKeys();
  } catch (e) {
    const msg = e instanceof Error ? e.message : "Unknown error";
    logger.error("Failed to fetch Google JWKS", { error: msg });
    return err({
      code: "JWKS_FETCH_FAILED",
      httpStatus: 401 as const,
      message: `Failed to fetch JWKS: ${msg}`,
    });
  }

  // Find the key matching the token's kid
  const matchingKey = header.kid
    ? keys.find((k) => k.kid === header.kid)
    : keys[0];

  if (!matchingKey) {
    logger.warn("id_token validation failed: no matching JWKS key", {
      kid: header.kid,
    });
    return err({
      code: "INVALID_SIGNATURE",
      httpStatus: 401 as const,
      message: "No matching key found in JWKS for token kid",
    });
  }

  try {
    const publicKey = await jwkToPublicKey(matchingKey);
    const valid = await verifySignature(signedContent, signatureBytes, publicKey);
    if (!valid) {
      logger.warn("id_token validation failed: invalid signature", {
        kid: header.kid,
      });
      return err({
        code: "INVALID_SIGNATURE",
        httpStatus: 401 as const,
        message: "id_token signature verification failed",
      });
    }
  } catch (e) {
    const msg = e instanceof Error ? e.message : "Unknown error";
    logger.warn("id_token validation failed: signature verification error", {
      error: msg,
    });
    return err({
      code: "INVALID_SIGNATURE",
      httpStatus: 401 as const,
      message: `Signature verification error: ${msg}`,
    });
  }

  // 3. Verify aud
  const aud = payload.aud as string | undefined;
  if (aud !== expectedAud) {
    logger.warn("id_token validation failed: aud mismatch", {
      expected: expectedAud,
      received: aud,
    });
    return err({
      code: "INVALID_AUD",
      httpStatus: 401 as const,
      message: `aud claim "${aud}" does not match expected "${expectedAud}"`,
    });
  }

  // 4. Verify iss
  const iss = payload.iss as string | undefined;
  if (iss !== expectedIss) {
    logger.warn("id_token validation failed: iss mismatch", {
      expected: expectedIss,
      received: iss,
    });
    return err({
      code: "INVALID_ISS",
      httpStatus: 401 as const,
      message: `iss claim "${iss}" does not match expected "${expectedIss}"`,
    });
  }

  // 5. Verify exp
  const exp = payload.exp as number | undefined;
  if (typeof exp !== "number" || exp <= nowSeconds) {
    logger.warn("id_token validation failed: token expired", {
      exp,
      now: nowSeconds,
    });
    return err({
      code: "TOKEN_EXPIRED",
      httpStatus: 401 as const,
      message: "id_token has expired",
    });
  }

  // 6. Extract claims
  const sub = payload.sub as string | undefined;
  const email = payload.email as string | undefined;
  const name = payload.name as string | undefined;

  if (!sub || !email) {
    logger.warn("id_token validation failed: missing required claims", {
      hasSub: !!sub,
      hasEmail: !!email,
    });
    return err({
      code: "MISSING_CLAIMS",
      httpStatus: 401 as const,
      message: "id_token missing required claims (sub, email)",
    });
  }

  logger.info("id_token validated successfully", { sub, email });

  return ok({
    sub,
    email,
    name: name ?? "",
    picture: payload.picture as string | undefined,
    emailVerified: payload.email_verified as boolean | undefined,
  });
}
