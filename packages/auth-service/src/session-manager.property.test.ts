// Property-based tests for SessionManager — Session Token Construction
// **Validates: Requirements 2.1, 2.6**
// Property 6: Session Token Construction — For any authenticated user with a
// tenantId and subject ID, the issued session JWT SHALL contain the `tenantId`,
// `sub` (user subject ID), and `iat` (issued-at timestamp) fields, with `exp`
// equal to `iat + 900 seconds` (15 minutes), and the accompanying refresh token
// SHALL have an expiration of `iat + 28800 seconds` (8 hours).

import { describe, it, expect } from "vitest";
import * as fc from "fast-check";
import { randomBytes } from "node:crypto";
import { createLogger } from "@clearfin/shared";
import { SessionManager } from "./session-manager.js";
import type { SessionManagerConfig } from "./session-manager.js";

// ── Helpers ──────────────────────────────────────────────────────────

const silentLogger = createLogger("test", "test-corr-id", {}, () => {});

function makeConfig(): SessionManagerConfig {
  return {
    signingSecret: "test-secret-key-at-least-32-bytes-long!!",
    encryptionKey: randomBytes(32),
  };
}

/** Decode a JWT payload without signature verification. */
function decodeJwtPayload(jwt: string): Record<string, unknown> {
  const parts = jwt.split(".");
  return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
}

// ── Generators ───────────────────────────────────────────────────────

/** Non-empty alphanumeric string for sub / tenantId values. */
const nonEmptyIdArb = fc.stringMatching(/^[a-zA-Z0-9_-]{1,64}$/);

/** Reasonable epoch-seconds timestamp (2020-01-01 to 2035-01-01). */
const timestampArb = fc.integer({ min: 1577836800, max: 2051222400 });

// ── Property 6 ───────────────────────────────────────────────────────

describe("Property 6: Session Token Construction", () => {
  it("JWT contains correct sub, tenantId, and iat fields", () => {
    fc.assert(
      fc.property(nonEmptyIdArb, nonEmptyIdArb, timestampArb, (sub, tenantId, nowSeconds) => {
        const manager = new SessionManager(makeConfig(), silentLogger);
        const result = manager.createSession({ sub }, tenantId, nowSeconds);

        expect(result.ok).toBe(true);
        if (!result.ok) return;

        const payload = decodeJwtPayload(result.value.jwt);
        expect(payload.sub).toBe(sub);
        expect(payload.tenantId).toBe(tenantId);
        expect(payload.iat).toBe(nowSeconds);
      }),
      { numRuns: 200 },
    );
  });

  it("JWT exp equals iat + 900 seconds (15 minutes)", () => {
    fc.assert(
      fc.property(nonEmptyIdArb, nonEmptyIdArb, timestampArb, (sub, tenantId, nowSeconds) => {
        const manager = new SessionManager(makeConfig(), silentLogger);
        const result = manager.createSession({ sub }, tenantId, nowSeconds);

        expect(result.ok).toBe(true);
        if (!result.ok) return;

        const payload = decodeJwtPayload(result.value.jwt);
        expect(payload.exp).toBe(nowSeconds + 900);
      }),
      { numRuns: 200 },
    );
  });

  it("refresh token expiresAt equals issuedAt + 28800 seconds (8 hours)", () => {
    fc.assert(
      fc.property(nonEmptyIdArb, nonEmptyIdArb, timestampArb, (sub, tenantId, nowSeconds) => {
        const manager = new SessionManager(makeConfig(), silentLogger);
        const result = manager.createSession({ sub }, tenantId, nowSeconds);

        expect(result.ok).toBe(true);
        if (!result.ok) return;

        const rt = manager.getRefreshToken(result.value.refreshTokenId);
        expect(rt).toBeDefined();
        if (!rt) return;

        const issuedAtEpochMs = nowSeconds * 1000;
        const expectedExpiresAtMs = (nowSeconds + 28800) * 1000;

        expect(rt.issuedAt.getTime()).toBe(issuedAtEpochMs);
        expect(rt.expiresAt.getTime()).toBe(expectedExpiresAtMs);
      }),
      { numRuns: 200 },
    );
  });

  it("JWT and refresh token share the same tokenFamily", () => {
    fc.assert(
      fc.property(nonEmptyIdArb, nonEmptyIdArb, timestampArb, (sub, tenantId, nowSeconds) => {
        const manager = new SessionManager(makeConfig(), silentLogger);
        const result = manager.createSession({ sub }, tenantId, nowSeconds);

        expect(result.ok).toBe(true);
        if (!result.ok) return;

        const payload = decodeJwtPayload(result.value.jwt);
        const rt = manager.getRefreshToken(result.value.refreshTokenId);
        expect(rt).toBeDefined();
        if (!rt) return;

        expect(payload.tokenFamily).toBeTypeOf("string");
        expect((payload.tokenFamily as string).length).toBeGreaterThan(0);
        expect(rt.tokenFamily).toBe(payload.tokenFamily);
      }),
      { numRuns: 200 },
    );
  });
});

// ── Property 7: Refresh Token Rotation ───────────────────────────────
// **Validates: Requirements 2.4**
// For any valid refresh token that is consumed during a refresh operation,
// the Auth_Service SHALL mark the original token as consumed and issue a new
// refresh token with a new ID but the same token family, such that the
// original token is no longer usable.

describe("Property 7: Refresh Token Rotation", () => {
  it("after refresh, the original token is marked as consumed", () => {
    fc.assert(
      fc.property(nonEmptyIdArb, nonEmptyIdArb, timestampArb, (sub, tenantId, nowSeconds) => {
        const manager = new SessionManager(makeConfig(), silentLogger);
        const session = manager.createSession({ sub }, tenantId, nowSeconds);
        expect(session.ok).toBe(true);
        if (!session.ok) return;

        const originalId = session.value.refreshTokenId;

        // Refresh within the token's lifetime
        const refreshTime = nowSeconds + 60;
        const refreshResult = manager.refreshSession(originalId, refreshTime);
        expect(refreshResult.ok).toBe(true);

        const originalToken = manager.getRefreshToken(originalId);
        expect(originalToken).toBeDefined();
        expect(originalToken!.consumed).toBe(true);
      }),
      { numRuns: 200 },
    );
  });

  it("a new refresh token is issued with a different ID", () => {
    fc.assert(
      fc.property(nonEmptyIdArb, nonEmptyIdArb, timestampArb, (sub, tenantId, nowSeconds) => {
        const manager = new SessionManager(makeConfig(), silentLogger);
        const session = manager.createSession({ sub }, tenantId, nowSeconds);
        expect(session.ok).toBe(true);
        if (!session.ok) return;

        const originalId = session.value.refreshTokenId;
        const refreshTime = nowSeconds + 60;
        const refreshResult = manager.refreshSession(originalId, refreshTime);
        expect(refreshResult.ok).toBe(true);
        if (!refreshResult.ok) return;

        expect(refreshResult.value.refreshTokenId).not.toBe(originalId);
      }),
      { numRuns: 200 },
    );
  });

  it("the new refresh token has the same tokenFamily as the original", () => {
    fc.assert(
      fc.property(nonEmptyIdArb, nonEmptyIdArb, timestampArb, (sub, tenantId, nowSeconds) => {
        const manager = new SessionManager(makeConfig(), silentLogger);
        const session = manager.createSession({ sub }, tenantId, nowSeconds);
        expect(session.ok).toBe(true);
        if (!session.ok) return;

        const originalId = session.value.refreshTokenId;
        const originalToken = manager.getRefreshToken(originalId);
        expect(originalToken).toBeDefined();

        const refreshTime = nowSeconds + 60;
        const refreshResult = manager.refreshSession(originalId, refreshTime);
        expect(refreshResult.ok).toBe(true);
        if (!refreshResult.ok) return;

        const newToken = manager.getRefreshToken(refreshResult.value.refreshTokenId);
        expect(newToken).toBeDefined();
        expect(newToken!.tokenFamily).toBe(originalToken!.tokenFamily);
      }),
      { numRuns: 200 },
    );
  });

  it("the original token is no longer usable (second refresh attempt fails with TOKEN_REPLAY_DETECTED)", () => {
    fc.assert(
      fc.property(nonEmptyIdArb, nonEmptyIdArb, timestampArb, (sub, tenantId, nowSeconds) => {
        const manager = new SessionManager(makeConfig(), silentLogger);
        const session = manager.createSession({ sub }, tenantId, nowSeconds);
        expect(session.ok).toBe(true);
        if (!session.ok) return;

        const originalId = session.value.refreshTokenId;

        // First refresh succeeds
        const refreshTime = nowSeconds + 60;
        const firstRefresh = manager.refreshSession(originalId, refreshTime);
        expect(firstRefresh.ok).toBe(true);

        // Second refresh with the same (now consumed) token fails
        const replayTime = nowSeconds + 120;
        const replayResult = manager.refreshSession(originalId, replayTime);
        expect(replayResult.ok).toBe(false);
        if (replayResult.ok) return;
        expect(replayResult.error.code).toBe("TOKEN_REPLAY_DETECTED");
      }),
      { numRuns: 200 },
    );
  });
});

// ── Property 8: Token Family Revocation on Replay ────────────────────
// **Validates: Requirements 2.5**
// For any token family with N rotations, if a previously consumed refresh
// token is presented, the Auth_Service SHALL revoke all tokens in that
// token family (both consumed and active) and terminate the associated session.

describe("Property 8: Token Family Revocation on Replay", () => {
  /** Generator: number of rotations (1-5). */
  const rotationCountArb = fc.integer({ min: 1, max: 5 });

  /**
   * Helper: create a session and perform `rotations` successive refreshes.
   * Returns the ordered list of refresh token IDs (index 0 = original).
   */
  function buildTokenChain(
    manager: SessionManager,
    sub: string,
    tenantId: string,
    baseTime: number,
    rotations: number,
  ): string[] {
    const session = manager.createSession({ sub }, tenantId, baseTime);
    expect(session.ok).toBe(true);
    if (!session.ok) return [];

    const chain: string[] = [session.value.refreshTokenId];

    for (let i = 0; i < rotations; i++) {
      const refreshTime = baseTime + 60 * (i + 1);
      const result = manager.refreshSession(chain[chain.length - 1], refreshTime);
      expect(result.ok).toBe(true);
      if (!result.ok) return chain;
      chain.push(result.value.refreshTokenId);
    }

    return chain;
  }

  it("replaying a consumed token returns TOKEN_REPLAY_DETECTED", () => {
    fc.assert(
      fc.property(
        nonEmptyIdArb,
        nonEmptyIdArb,
        timestampArb,
        rotationCountArb,
        (sub, tenantId, baseTime, rotations) => {
          const manager = new SessionManager(makeConfig(), silentLogger);
          const chain = buildTokenChain(manager, sub, tenantId, baseTime, rotations);
          expect(chain.length).toBe(rotations + 1);

          // Pick a random consumed token (any token except the last, which is active)
          const replayIndex = Math.floor(Math.random() * rotations); // 0..rotations-1
          const replayTokenId = chain[replayIndex];

          const replayTime = baseTime + 60 * (rotations + 1);
          const replayResult = manager.refreshSession(replayTokenId, replayTime);

          expect(replayResult.ok).toBe(false);
          if (replayResult.ok) return;
          expect(replayResult.error.code).toBe("TOKEN_REPLAY_DETECTED");
        },
      ),
      { numRuns: 200 },
    );
  });

  it("after replay, ALL tokens in the family have revokedAt set (consumed and active)", () => {
    fc.assert(
      fc.property(
        nonEmptyIdArb,
        nonEmptyIdArb,
        timestampArb,
        rotationCountArb,
        (sub, tenantId, baseTime, rotations) => {
          const manager = new SessionManager(makeConfig(), silentLogger);
          const chain = buildTokenChain(manager, sub, tenantId, baseTime, rotations);
          expect(chain.length).toBe(rotations + 1);

          // Replay the first (original) consumed token
          const replayTime = baseTime + 60 * (rotations + 1);
          const replayResult = manager.refreshSession(chain[0], replayTime);
          expect(replayResult.ok).toBe(false);

          // Every token in the chain must now have revokedAt set
          for (const tokenId of chain) {
            const token = manager.getRefreshToken(tokenId);
            expect(token).toBeDefined();
            expect(token!.revokedAt).not.toBeNull();
            expect(token!.revokedAt).toBeInstanceOf(Date);
          }
        },
      ),
      { numRuns: 200 },
    );
  });

  it("replay at any position in the chain revokes the entire family", () => {
    fc.assert(
      fc.property(
        nonEmptyIdArb,
        nonEmptyIdArb,
        timestampArb,
        rotationCountArb,
        // replayPosition: which consumed token to replay (0-based index into consumed tokens)
        fc.integer({ min: 0, max: 4 }),
        (sub, tenantId, baseTime, rotations, replayOffset) => {
          const manager = new SessionManager(makeConfig(), silentLogger);
          const chain = buildTokenChain(manager, sub, tenantId, baseTime, rotations);
          expect(chain.length).toBe(rotations + 1);

          // Clamp replay position to valid consumed range (0..rotations-1)
          const replayIndex = replayOffset % rotations;
          const replayTokenId = chain[replayIndex];

          const replayTime = baseTime + 60 * (rotations + 1);
          manager.refreshSession(replayTokenId, replayTime);

          // Verify every token in the family is revoked
          for (const tokenId of chain) {
            const token = manager.getRefreshToken(tokenId);
            expect(token).toBeDefined();
            expect(token!.revokedAt).not.toBeNull();
          }
        },
      ),
      { numRuns: 200 },
    );
  });
});
