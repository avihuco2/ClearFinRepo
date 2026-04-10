// Property-based tests for CallbackValidator rate limiting
// **Validates: Requirements 7.1**
// Property 19: Callback Rate Limiting — For any source IP address, the
// Callback_Validator SHALL allow up to 10 requests within a 60-second window
// and return HTTP 429 for every subsequent request within that window.

import { describe, it, expect } from "vitest";
import * as fc from "fast-check";
import { CallbackValidator } from "./callback-validator.js";
import { createLogger } from "@clearfin/shared";

/** Silent logger that swallows output during tests. */
const silentLogger = createLogger("test", "test-corr-id", {}, () => {});

/** Generator for valid IPv4 addresses. */
const ipArb = fc
  .tuple(
    fc.integer({ min: 1, max: 255 }),
    fc.integer({ min: 0, max: 255 }),
    fc.integer({ min: 0, max: 255 }),
    fc.integer({ min: 1, max: 254 }),
  )
  .map(([a, b, c, d]) => `${a}.${b}.${c}.${d}`);

describe("Property 19: Callback Rate Limiting", () => {
  it("allows up to 10 requests and rejects the rest within a 60-second window", () => {
    fc.assert(
      fc.property(
        ipArb,
        fc.integer({ min: 1, max: 30 }),
        (sourceIp, totalRequests) => {
          const fixedTime = new Date("2025-01-01T00:00:00Z");
          const validator = new CallbackValidator(silentLogger, () => fixedTime);

          for (let i = 1; i <= totalRequests; i++) {
            const result = validator.checkRateLimit(sourceIp);
            if (i <= 10) {
              expect(result.ok).toBe(true);
            } else {
              expect(result.ok).toBe(false);
              if (!result.ok) {
                expect(result.error.code).toBe("RATE_LIMIT_EXCEEDED");
                expect(result.error.httpStatus).toBe(429);
                expect(result.error.sourceIp).toBe(sourceIp);
              }
            }
          }
        },
      ),
      { numRuns: 200 },
    );
  });

  it("different IPs have independent rate limits", () => {
    fc.assert(
      fc.property(
        ipArb,
        ipArb,
        (ipA, ipB) => {
          // Skip when both IPs are the same — independence only applies to distinct IPs
          fc.pre(ipA !== ipB);

          const fixedTime = new Date("2025-01-01T00:00:00Z");
          const validator = new CallbackValidator(silentLogger, () => fixedTime);

          // Exhaust the rate limit for ipA (10 allowed + 5 rejected)
          for (let i = 0; i < 15; i++) {
            validator.checkRateLimit(ipA);
          }

          // ipB should still be fully allowed — its window is independent
          for (let i = 1; i <= 10; i++) {
            const result = validator.checkRateLimit(ipB);
            expect(result.ok).toBe(true);
          }

          // ipB's 11th request should be rejected
          const rejected = validator.checkRateLimit(ipB);
          expect(rejected.ok).toBe(false);
          if (!rejected.ok) {
            expect(rejected.error.httpStatus).toBe(429);
          }
        },
      ),
      { numRuns: 100 },
    );
  });

  it("resets the window after 60 seconds elapse", () => {
    fc.assert(
      fc.property(
        ipArb,
        fc.integer({ min: 1, max: 10 }),
        (sourceIp, firstBatchSize) => {
          let currentTime = new Date("2025-01-01T00:00:00Z");
          const validator = new CallbackValidator(silentLogger, () => currentTime);

          // Use up some requests in the first window
          for (let i = 0; i < firstBatchSize; i++) {
            const r = validator.checkRateLimit(sourceIp);
            expect(r.ok).toBe(true);
          }

          // Advance time past the 60-second window
          currentTime = new Date(currentTime.getTime() + 60_000);

          // After window reset, all 10 requests should be allowed again
          for (let i = 1; i <= 10; i++) {
            const result = validator.checkRateLimit(sourceIp);
            expect(result.ok).toBe(true);
          }

          // 11th request in the new window should be rejected
          const rejected = validator.checkRateLimit(sourceIp);
          expect(rejected.ok).toBe(false);
          if (!rejected.ok) {
            expect(rejected.error.httpStatus).toBe(429);
          }
        },
      ),
      { numRuns: 100 },
    );
  });
});

// ── Property 20: Callback Input Validation ───────────────────────────
// **Validates: Requirements 7.2, 7.3**
// For any callback request, the Callback_Validator SHALL reject the request if:
// (a) the `code` parameter exceeds 2048 characters,
// (b) the `code` parameter contains non-URL-safe characters, or
// (c) the query parameters include any key not in {state, code, scope, authuser}.
// All requests meeting all three criteria SHALL be accepted.

/** Characters considered URL-safe by the implementation. */
const URL_SAFE_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/=";

/** Generator for a string composed only of URL-safe characters. */
const urlSafeStringArb = (constraints: { minLength?: number; maxLength?: number }) =>
  fc
    .array(
      fc.integer({ min: 0, max: URL_SAFE_CHARS.length - 1 }).map((i) => URL_SAFE_CHARS[i]),
      { minLength: constraints.minLength ?? 1, maxLength: constraints.maxLength ?? 100 },
    )
    .map((chars) => chars.join(""));

/** Allowed query parameter keys. */
const ALLOWED_KEYS = ["state", "code", "scope", "authuser"] as const;

/** Generator for a key that is NOT in the allowed set. */
const unexpectedKeyArb = fc
  .stringMatching(/^[a-z][a-z0-9_]{0,15}$/)
  .filter((k) => !new Set(ALLOWED_KEYS).has(k as any));

describe("Property 20: Callback Input Validation", () => {
  // Helper — fresh validator per test run
  const makeValidator = () =>
    new CallbackValidator(silentLogger, () => new Date("2025-01-01T00:00:00Z"));

  // ── (a) Code exceeding 2048 characters SHALL be rejected ───────────

  it("rejects code that exceeds 2048 characters", () => {
    fc.assert(
      fc.property(
        urlSafeStringArb({ minLength: 2049, maxLength: 3000 }),
        (longCode) => {
          const result = makeValidator().validateParameters({ state: "s", code: longCode });
          expect(result.ok).toBe(false);
          if (!result.ok) {
            expect(result.error.code).toBe("INVALID_PARAMETERS");
            expect(result.error.httpStatus).toBe(400);
            expect(result.error.reasons.some((r: string) => r.includes("2048"))).toBe(true);
          }
        },
      ),
      { numRuns: 100 },
    );
  });

  // ── (b) Code with non-URL-safe characters SHALL be rejected ────────

  it("rejects code containing non-URL-safe characters", () => {
    // Generate a code that has at least one non-URL-safe char
    const nonUrlSafeCodeArb = fc
      .tuple(
        urlSafeStringArb({ minLength: 0, maxLength: 50 }),
        fc.char().filter((c) => !URL_SAFE_CHARS.includes(c)),
        urlSafeStringArb({ minLength: 0, maxLength: 50 }),
      )
      .map(([prefix, bad, suffix]) => prefix + bad + suffix)
      .filter((s) => s.length > 0 && s.length <= 2048);

    fc.assert(
      fc.property(nonUrlSafeCodeArb, (badCode) => {
        const result = makeValidator().validateParameters({ state: "s", code: badCode });
        expect(result.ok).toBe(false);
        if (!result.ok) {
          expect(result.error.code).toBe("INVALID_PARAMETERS");
          expect(result.error.httpStatus).toBe(400);
          expect(result.error.reasons.some((r: string) => r.includes("non-URL-safe"))).toBe(true);
        }
      }),
      { numRuns: 100 },
    );
  });

  // ── (c) Unexpected query parameters SHALL be rejected ──────────────

  it("rejects requests with unexpected query parameter keys", () => {
    fc.assert(
      fc.property(
        unexpectedKeyArb,
        urlSafeStringArb({ minLength: 1, maxLength: 100 }),
        (extraKey, extraValue) => {
          const params: Record<string, string> = {
            state: "s",
            code: "validCode123",
            [extraKey]: extraValue,
          };
          const result = makeValidator().validateParameters(params);
          expect(result.ok).toBe(false);
          if (!result.ok) {
            expect(result.error.code).toBe("INVALID_PARAMETERS");
            expect(result.error.httpStatus).toBe(400);
            expect(result.error.reasons.some((r: string) => r.includes("unexpected"))).toBe(true);
          }
        },
      ),
      { numRuns: 100 },
    );
  });

  // ── Valid requests meeting all criteria SHALL be accepted ───────────

  it("accepts requests with valid code (≤2048 URL-safe chars) and only allowed keys", () => {
    // Generate a subset of allowed optional keys
    const optionalKeysArb = fc.subarray(["scope", "authuser"] as const);

    fc.assert(
      fc.property(
        urlSafeStringArb({ minLength: 1, maxLength: 2048 }),
        urlSafeStringArb({ minLength: 1, maxLength: 64 }),
        optionalKeysArb,
        (code, state, optionalKeys) => {
          const params: Record<string, string> = { state, code };
          for (const key of optionalKeys) {
            params[key] = "somevalue";
          }
          const result = makeValidator().validateParameters(params);
          expect(result.ok).toBe(true);
          if (result.ok) {
            expect(result.value.code).toBe(code);
            expect(result.value.state).toBe(state);
          }
        },
      ),
      { numRuns: 200 },
    );
  });
});

// ── Property 21: Brute-Force Detection and Blocking ──────────────────
// **Validates: Requirements 7.4**
// For any source IP address, if 5 consecutive callback validations fail
// within a 5-minute window, the Callback_Validator SHALL block that IP for
// 15 minutes and log a brute-force alert. Non-consecutive failures
// (interrupted by a success) SHALL NOT trigger blocking.

describe("Property 21: Brute-Force Detection and Blocking", () => {
  /** Generator for a count of consecutive failures that triggers blocking (≥5). */
  const triggeringFailureCountArb = fc.integer({ min: 5, max: 20 });

  /** Generator for a count of consecutive failures that does NOT trigger blocking (<5). */
  const nonTriggeringFailureCountArb = fc.integer({ min: 1, max: 4 });

  it("blocks an IP after 5 consecutive failures within a 5-minute window", () => {
    fc.assert(
      fc.property(
        ipArb,
        triggeringFailureCountArb,
        (sourceIp, failureCount) => {
          const fixedTime = new Date("2025-01-01T00:00:00Z");
          const validator = new CallbackValidator(silentLogger, () => fixedTime);

          // Record `failureCount` consecutive failures
          for (let i = 0; i < failureCount; i++) {
            validator.recordFailure(sourceIp);
          }

          // The IP should now be blocked
          const result = validator.checkBruteForce(sourceIp);
          expect(result.ok).toBe(false);
          if (!result.ok) {
            expect(result.error.code).toBe("IP_BLOCKED");
            expect(result.error.httpStatus).toBe(429);
            expect(result.error.sourceIp).toBe(sourceIp);
          }
        },
      ),
      { numRuns: 200 },
    );
  });

  it("does NOT block an IP with fewer than 5 consecutive failures", () => {
    fc.assert(
      fc.property(
        ipArb,
        nonTriggeringFailureCountArb,
        (sourceIp, failureCount) => {
          const fixedTime = new Date("2025-01-01T00:00:00Z");
          const validator = new CallbackValidator(silentLogger, () => fixedTime);

          for (let i = 0; i < failureCount; i++) {
            validator.recordFailure(sourceIp);
          }

          const result = validator.checkBruteForce(sourceIp);
          expect(result.ok).toBe(true);
        },
      ),
      { numRuns: 200 },
    );
  });

  it("does NOT trigger blocking when a success interrupts consecutive failures", () => {
    fc.assert(
      fc.property(
        ipArb,
        nonTriggeringFailureCountArb,
        nonTriggeringFailureCountArb,
        (sourceIp, failuresBefore, failuresAfter) => {
          const fixedTime = new Date("2025-01-01T00:00:00Z");
          const validator = new CallbackValidator(silentLogger, () => fixedTime);

          // Record some failures, then a success, then more failures
          for (let i = 0; i < failuresBefore; i++) {
            validator.recordFailure(sourceIp);
          }

          // A success resets the consecutive failure counter
          validator.recordSuccess(sourceIp);

          for (let i = 0; i < failuresAfter; i++) {
            validator.recordFailure(sourceIp);
          }

          // Neither batch alone reaches 5, so the IP should NOT be blocked
          const result = validator.checkBruteForce(sourceIp);
          expect(result.ok).toBe(true);
        },
      ),
      { numRuns: 200 },
    );
  });

  it("blocks the IP for exactly 15 minutes and unblocks after", () => {
    fc.assert(
      fc.property(
        ipArb,
        fc.integer({ min: 0, max: 14 }),
        (sourceIp, minutesBefore15) => {
          let currentTime = new Date("2025-01-01T00:00:00Z");
          const validator = new CallbackValidator(silentLogger, () => currentTime);

          // Trigger the block with 5 consecutive failures
          for (let i = 0; i < 5; i++) {
            validator.recordFailure(sourceIp);
          }

          // Still blocked at minutesBefore15 minutes (0–14 min after block)
          currentTime = new Date(
            currentTime.getTime() + minutesBefore15 * 60_000,
          );
          const stillBlocked = validator.checkBruteForce(sourceIp);
          expect(stillBlocked.ok).toBe(false);

          // Unblocked at exactly 15 minutes after the block was set
          currentTime = new Date("2025-01-01T00:15:00Z");
          const unblocked = validator.checkBruteForce(sourceIp);
          expect(unblocked.ok).toBe(true);
        },
      ),
      { numRuns: 200 },
    );
  });

  it("different IPs have independent brute-force tracking", () => {
    fc.assert(
      fc.property(
        ipArb,
        ipArb,
        (ipA, ipB) => {
          fc.pre(ipA !== ipB);

          const fixedTime = new Date("2025-01-01T00:00:00Z");
          const validator = new CallbackValidator(silentLogger, () => fixedTime);

          // Block ipA with 5 consecutive failures
          for (let i = 0; i < 5; i++) {
            validator.recordFailure(ipA);
          }

          // ipA should be blocked
          const resultA = validator.checkBruteForce(ipA);
          expect(resultA.ok).toBe(false);

          // ipB should NOT be blocked
          const resultB = validator.checkBruteForce(ipB);
          expect(resultB.ok).toBe(true);
        },
      ),
      { numRuns: 100 },
    );
  });
});
