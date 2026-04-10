import { describe, it, expect, beforeAll } from "vitest";
import { generateKeyPairSync, createSign, KeyObject } from "node:crypto";
import { createLogger } from "@clearfin/shared";
import { validateIdToken } from "./id-token-validator.js";
import type { JwksFetcher, JWK } from "./id-token-validator.js";

// ── Test helpers ─────────────────────────────────────────────────────

const silentLogger = createLogger("test", "test-corr-id", {}, () => {});

/** Base64url-encode a buffer or string. */
function base64url(input: Buffer | string): string {
  const buf = typeof input === "string" ? Buffer.from(input) : input;
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Build a signed JWT from a payload using the given RSA private key. */
function buildJwt(
  payload: Record<string, unknown>,
  privateKey: KeyObject,
  kid: string,
): string {
  const header = base64url(JSON.stringify({ alg: "RS256", typ: "JWT", kid }));
  const body = base64url(JSON.stringify(payload));
  const signedContent = `${header}.${body}`;

  const signer = createSign("RSA-SHA256");
  signer.update(signedContent);
  const signature = signer.sign(privateKey);

  return `${signedContent}.${base64url(signature)}`;
}

/** Extract JWK (public) components from a KeyObject. */
function keyToJwk(publicKey: KeyObject, kid: string): JWK {
  const exported = publicKey.export({ format: "jwk" }) as {
    kty: string;
    n: string;
    e: string;
  };
  return { kty: exported.kty, kid, n: exported.n, e: exported.e, alg: "RS256", use: "sig" };
}

// ── Shared fixtures ──────────────────────────────────────────────────

let privateKey: KeyObject;
let publicKey: KeyObject;
let jwk: JWK;
const KID = "test-kid-1";
const CLIENT_ID = "my-client-id.apps.googleusercontent.com";
const ISSUER = "https://accounts.google.com";

beforeAll(() => {
  const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
  privateKey = pair.privateKey;
  publicKey = pair.publicKey;
  jwk = keyToJwk(publicKey, KID);
});

function makeFetcher(keys: JWK[]): JwksFetcher {
  return { fetchKeys: async () => keys };
}

function validPayload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    sub: "google-subject-123",
    email: "user@example.com",
    name: "Test User",
    aud: CLIENT_ID,
    iss: ISSUER,
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000) - 60,
    ...overrides,
  };
}

// ── Tests ────────────────────────────────────────────────────────────

describe("IdTokenValidator", () => {
  describe("valid token", () => {
    it("returns UserClaims for a correctly signed token with valid claims", async () => {
      const payload = validPayload();
      const token = buildJwt(payload, privateKey, KID);
      const fetcher = makeFetcher([jwk]);

      const result = await validateIdToken(token, CLIENT_ID, ISSUER, fetcher, silentLogger);

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value.sub).toBe("google-subject-123");
        expect(result.value.email).toBe("user@example.com");
        expect(result.value.name).toBe("Test User");
      }
    });

    it("returns optional picture and emailVerified when present", async () => {
      const payload = validPayload({
        picture: "https://example.com/photo.jpg",
        email_verified: true,
      });
      const token = buildJwt(payload, privateKey, KID);
      const fetcher = makeFetcher([jwk]);

      const result = await validateIdToken(token, CLIENT_ID, ISSUER, fetcher, silentLogger);

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value.picture).toBe("https://example.com/photo.jpg");
        expect(result.value.emailVerified).toBe(true);
      }
    });
  });

  describe("invalid signature", () => {
    it("rejects a token signed with a different key", async () => {
      const otherPair = generateKeyPairSync("rsa", { modulusLength: 2048 });
      const token = buildJwt(validPayload(), otherPair.privateKey, KID);
      const fetcher = makeFetcher([jwk]); // original public key

      const result = await validateIdToken(token, CLIENT_ID, ISSUER, fetcher, silentLogger);

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.code).toBe("INVALID_SIGNATURE");
        expect(result.error.httpStatus).toBe(401);
      }
    });

    it("rejects when no matching kid in JWKS", async () => {
      const token = buildJwt(validPayload(), privateKey, "unknown-kid");
      const fetcher = makeFetcher([jwk]); // jwk has kid "test-kid-1"

      const result = await validateIdToken(token, CLIENT_ID, ISSUER, fetcher, silentLogger);

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.code).toBe("INVALID_SIGNATURE");
        expect(result.error.httpStatus).toBe(401);
      }
    });
  });

  describe("wrong aud", () => {
    it("rejects when aud does not match expected client ID", async () => {
      const payload = validPayload({ aud: "wrong-client-id" });
      const token = buildJwt(payload, privateKey, KID);
      const fetcher = makeFetcher([jwk]);

      const result = await validateIdToken(token, CLIENT_ID, ISSUER, fetcher, silentLogger);

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.code).toBe("INVALID_AUD");
        expect(result.error.httpStatus).toBe(401);
        expect(result.error.message).toContain("wrong-client-id");
      }
    });
  });

  describe("wrong iss", () => {
    it("rejects when iss does not match expected issuer", async () => {
      const payload = validPayload({ iss: "https://evil.example.com" });
      const token = buildJwt(payload, privateKey, KID);
      const fetcher = makeFetcher([jwk]);

      const result = await validateIdToken(token, CLIENT_ID, ISSUER, fetcher, silentLogger);

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.code).toBe("INVALID_ISS");
        expect(result.error.httpStatus).toBe(401);
        expect(result.error.message).toContain("evil.example.com");
      }
    });
  });

  describe("expired token", () => {
    it("rejects when exp is in the past", async () => {
      const pastExp = Math.floor(Date.now() / 1000) - 600;
      const payload = validPayload({ exp: pastExp });
      const token = buildJwt(payload, privateKey, KID);
      const fetcher = makeFetcher([jwk]);

      const result = await validateIdToken(token, CLIENT_ID, ISSUER, fetcher, silentLogger);

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.code).toBe("TOKEN_EXPIRED");
        expect(result.error.httpStatus).toBe(401);
      }
    });

    it("rejects when exp equals current time (boundary)", async () => {
      const now = Math.floor(Date.now() / 1000);
      const payload = validPayload({ exp: now });
      const token = buildJwt(payload, privateKey, KID);
      const fetcher = makeFetcher([jwk]);

      const result = await validateIdToken(token, CLIENT_ID, ISSUER, fetcher, silentLogger, now);

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.code).toBe("TOKEN_EXPIRED");
      }
    });
  });

  describe("malformed token", () => {
    it("rejects a non-JWT string", async () => {
      const fetcher = makeFetcher([jwk]);
      const result = await validateIdToken("not-a-jwt", CLIENT_ID, ISSUER, fetcher, silentLogger);

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.code).toBe("MALFORMED_TOKEN");
        expect(result.error.httpStatus).toBe(401);
      }
    });

    it("rejects a token with only two parts", async () => {
      const fetcher = makeFetcher([jwk]);
      const result = await validateIdToken("a.b", CLIENT_ID, ISSUER, fetcher, silentLogger);

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.code).toBe("MALFORMED_TOKEN");
      }
    });
  });

  describe("missing claims", () => {
    it("rejects when sub is missing", async () => {
      const payload = validPayload();
      delete payload.sub;
      const token = buildJwt(payload, privateKey, KID);
      const fetcher = makeFetcher([jwk]);

      const result = await validateIdToken(token, CLIENT_ID, ISSUER, fetcher, silentLogger);

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.code).toBe("MISSING_CLAIMS");
        expect(result.error.httpStatus).toBe(401);
      }
    });

    it("rejects when email is missing", async () => {
      const payload = validPayload();
      delete payload.email;
      const token = buildJwt(payload, privateKey, KID);
      const fetcher = makeFetcher([jwk]);

      const result = await validateIdToken(token, CLIENT_ID, ISSUER, fetcher, silentLogger);

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.code).toBe("MISSING_CLAIMS");
      }
    });
  });

  describe("JWKS fetch failure", () => {
    it("returns JWKS_FETCH_FAILED when fetcher throws", async () => {
      const failingFetcher: JwksFetcher = {
        fetchKeys: async () => { throw new Error("Network timeout"); },
      };

      const token = buildJwt(validPayload(), privateKey, KID);
      const result = await validateIdToken(token, CLIENT_ID, ISSUER, failingFetcher, silentLogger);

      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.error.code).toBe("JWKS_FETCH_FAILED");
        expect(result.error.httpStatus).toBe(401);
        expect(result.error.message).toContain("Network timeout");
      }
    });
  });

  describe("defaults name to empty string", () => {
    it("returns empty name when name claim is absent", async () => {
      const payload = validPayload();
      delete payload.name;
      const token = buildJwt(payload, privateKey, KID);
      const fetcher = makeFetcher([jwk]);

      const result = await validateIdToken(token, CLIENT_ID, ISSUER, fetcher, silentLogger);

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value.name).toBe("");
      }
    });
  });
});
