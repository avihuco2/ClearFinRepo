// Property-based tests for id_token claim validation
// **Validates: Requirements 1.5, 1.6**
// Property 3: id_token Claim Validation — For any id_token, the Auth_Service
// SHALL accept the token if and only if the signature is valid against Google's
// JWKS, the `aud` claim matches the registered client ID, and the `iss` claim
// matches `https://accounts.google.com`. Any token failing any of these checks
// SHALL be rejected.

import { describe, it, expect, beforeAll } from "vitest";
import * as fc from "fast-check";
import { generateKeyPairSync, createSign, KeyObject } from "node:crypto";
import { createLogger } from "@clearfin/shared";
import { validateIdToken } from "./id-token-validator.js";
import type { JwksFetcher, JWK } from "./id-token-validator.js";

// ── Helpers ──────────────────────────────────────────────────────────

const silentLogger = createLogger("test", "test-corr-id", {}, () => {});

function base64url(input: Buffer | string): string {
  const buf = typeof input === "string" ? Buffer.from(input) : input;
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

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

function keyToJwk(publicKey: KeyObject, kid: string): JWK {
  const exported = publicKey.export({ format: "jwk" }) as {
    kty: string;
    n: string;
    e: string;
  };
  return { kty: exported.kty, kid, n: exported.n, e: exported.e, alg: "RS256", use: "sig" };
}

function makeFetcher(keys: JWK[]): JwksFetcher {
  return { fetchKeys: async () => keys };
}

// ── Fixtures ─────────────────────────────────────────────────────────

const EXPECTED_ISS = "https://accounts.google.com";
const KID = "prop-test-kid";

let correctPrivateKey: KeyObject;
let correctPublicKey: KeyObject;
let correctJwk: JWK;

let wrongPrivateKey: KeyObject;

beforeAll(() => {
  const correct = generateKeyPairSync("rsa", { modulusLength: 2048 });
  correctPrivateKey = correct.privateKey;
  correctPublicKey = correct.publicKey;
  correctJwk = keyToJwk(correctPublicKey, KID);

  const wrong = generateKeyPairSync("rsa", { modulusLength: 2048 });
  wrongPrivateKey = wrong.privateKey;
});

// ── Generators ───────────────────────────────────────────────────────

/** Random non-empty client ID string. */
const clientIdArb = fc.stringOf(
  fc.constantFrom(
    ..."abcdefghijklmnopqrstuvwxyz0123456789-.".split(""),
  ),
  { minLength: 5, maxLength: 64 },
);

/** Random non-empty string for aud values that won't match the expected client ID. */
const wrongAudArb = (expectedAud: string) =>
  clientIdArb.filter((v) => v !== expectedAud);

/** Random iss values that are NOT the expected Google issuer. */
const wrongIssArb = fc
  .stringOf(fc.constantFrom(..."abcdefghijklmnopqrstuvwxyz0123456789:/.".split("")), {
    minLength: 5,
    maxLength: 64,
  })
  .filter((v) => v !== EXPECTED_ISS);


// ── Property Tests ───────────────────────────────────────────────────

describe("Property 3: id_token Claim Validation", () => {
  it("accepts a token when signature is valid, aud matches, and iss matches", () => {
    fc.assert(
      fc.asyncProperty(clientIdArb, async (expectedAud) => {
        const now = Math.floor(Date.now() / 1000);
        const payload = {
          sub: "subject-123",
          email: "user@example.com",
          name: "Test User",
          aud: expectedAud,
          iss: EXPECTED_ISS,
          exp: now + 3600,
          iat: now - 60,
        };

        const token = buildJwt(payload, correctPrivateKey, KID);
        const fetcher = makeFetcher([correctJwk]);

        const result = await validateIdToken(
          token,
          expectedAud,
          EXPECTED_ISS,
          fetcher,
          silentLogger,
          now,
        );

        expect(result.ok).toBe(true);
      }),
      { numRuns: 100 },
    );
  });

  it("rejects a token signed with the wrong key (invalid signature)", () => {
    fc.assert(
      fc.asyncProperty(clientIdArb, async (expectedAud) => {
        const now = Math.floor(Date.now() / 1000);
        const payload = {
          sub: "subject-123",
          email: "user@example.com",
          name: "Test User",
          aud: expectedAud,
          iss: EXPECTED_ISS,
          exp: now + 3600,
          iat: now - 60,
        };

        // Sign with the WRONG private key, but verify against the CORRECT public key
        const token = buildJwt(payload, wrongPrivateKey, KID);
        const fetcher = makeFetcher([correctJwk]);

        const result = await validateIdToken(
          token,
          expectedAud,
          EXPECTED_ISS,
          fetcher,
          silentLogger,
          now,
        );

        expect(result.ok).toBe(false);
        if (!result.ok) {
          expect(result.error.code).toBe("INVALID_SIGNATURE");
          expect(result.error.httpStatus).toBe(401);
        }
      }),
      { numRuns: 100 },
    );
  });

  it("rejects a token when aud does not match the expected client ID", () => {
    fc.assert(
      fc.asyncProperty(clientIdArb, async (expectedAud) => {
        const tokenAud = expectedAud + "-wrong";
        const now = Math.floor(Date.now() / 1000);
        const payload = {
          sub: "subject-123",
          email: "user@example.com",
          name: "Test User",
          aud: tokenAud,
          iss: EXPECTED_ISS,
          exp: now + 3600,
          iat: now - 60,
        };

        // Valid signature, but aud mismatch
        const token = buildJwt(payload, correctPrivateKey, KID);
        const fetcher = makeFetcher([correctJwk]);

        const result = await validateIdToken(
          token,
          expectedAud,
          EXPECTED_ISS,
          fetcher,
          silentLogger,
          now,
        );

        expect(result.ok).toBe(false);
        if (!result.ok) {
          expect(result.error.code).toBe("INVALID_AUD");
          expect(result.error.httpStatus).toBe(401);
        }
      }),
      { numRuns: 100 },
    );
  });

  it("rejects a token when iss does not match https://accounts.google.com", () => {
    fc.assert(
      fc.asyncProperty(clientIdArb, wrongIssArb, async (expectedAud, badIss) => {
        const now = Math.floor(Date.now() / 1000);
        const payload = {
          sub: "subject-123",
          email: "user@example.com",
          name: "Test User",
          aud: expectedAud,
          iss: badIss,
          exp: now + 3600,
          iat: now - 60,
        };

        // Valid signature, correct aud, but wrong iss
        const token = buildJwt(payload, correctPrivateKey, KID);
        const fetcher = makeFetcher([correctJwk]);

        const result = await validateIdToken(
          token,
          expectedAud,
          EXPECTED_ISS,
          fetcher,
          silentLogger,
          now,
        );

        expect(result.ok).toBe(false);
        if (!result.ok) {
          expect(result.error.code).toBe("INVALID_ISS");
          expect(result.error.httpStatus).toBe(401);
        }
      }),
      { numRuns: 100 },
    );
  });

  it("biconditional: accepted iff signature valid AND aud matches AND iss matches", () => {
    // Generate all 8 combinations of (validSig, matchingAud, matchingIss)
    fc.assert(
      fc.asyncProperty(
        clientIdArb,
        fc.boolean(),
        fc.boolean(),
        fc.boolean(),
        async (expectedAud, useCorrectKey, useCorrectAud, useCorrectIss) => {
          const now = Math.floor(Date.now() / 1000);
          const tokenAud = useCorrectAud ? expectedAud : expectedAud + "-mismatch";
          const tokenIss = useCorrectIss ? EXPECTED_ISS : "https://evil.example.com";
          const signingKey = useCorrectKey ? correctPrivateKey : wrongPrivateKey;

          const payload = {
            sub: "subject-123",
            email: "user@example.com",
            name: "Test User",
            aud: tokenAud,
            iss: tokenIss,
            exp: now + 3600,
            iat: now - 60,
          };

          const token = buildJwt(payload, signingKey, KID);
          const fetcher = makeFetcher([correctJwk]);

          const result = await validateIdToken(
            token,
            expectedAud,
            EXPECTED_ISS,
            fetcher,
            silentLogger,
            now,
          );

          const allValid = useCorrectKey && useCorrectAud && useCorrectIss;

          if (allValid) {
            expect(result.ok).toBe(true);
          } else {
            expect(result.ok).toBe(false);
            if (!result.ok) {
              expect(result.error.httpStatus).toBe(401);
            }
          }
        },
      ),
      { numRuns: 200 },
    );
  });
});
