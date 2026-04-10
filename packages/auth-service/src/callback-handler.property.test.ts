// Property-based tests for callback handler — state parameter matching
// **Validates: Requirements 1.2, 1.3**
// Property 2: State Parameter Matching — For any pair of state values
// (stored vs returned), the Callback_Validator SHALL accept the callback
// if and only if the two state values are identical; all non-matching or
// missing state values SHALL be rejected.

import { describe, it, expect } from "vitest";
import * as fc from "fast-check";
import { handleCallback } from "./callback-handler.js";
import { CallbackValidator } from "./callback-validator.js";
import { SessionStore } from "./session-store.js";
import { createLogger } from "@clearfin/shared";

/** Silent logger that swallows output during tests. */
const silentLogger = createLogger("test", "test-corr-id", {}, () => {});

/** Fixed clock for deterministic tests. */
const fixedTime = new Date("2025-01-01T00:00:00Z");
const clock = () => fixedTime;

/** Generator for non-empty URL-safe state strings (mimics crypto random state values). */
const stateArb = fc
  .stringOf(
    fc.constantFrom(
      ..."ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~".split(""),
    ),
    { minLength: 1, maxLength: 128 },
  );

/** Generator for a valid URL-safe authorization code. */
const codeArb = fc
  .stringOf(
    fc.constantFrom(
      ..."ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/=".split(""),
    ),
    { minLength: 1, maxLength: 256 },
  );

/** Fresh validator + session store per property run. */
function makeContext() {
  const validator = new CallbackValidator(silentLogger, clock);
  const sessionStore = new SessionStore();
  return { validator, sessionStore };
}

describe("Property 2: State Parameter Matching", () => {
  it("accepts the callback when the returned state matches the stored state", () => {
    fc.assert(
      fc.property(stateArb, codeArb, (state, code) => {
        const { validator, sessionStore } = makeContext();

        // Store the state + a code verifier in the session store
        sessionStore.set(state, "test-code-verifier");

        const result = handleCallback(
          { state, code },
          "10.0.0.1",
          validator,
          sessionStore,
          silentLogger,
        );

        expect(result.ok).toBe(true);
        if (result.ok) {
          expect(result.value.code).toBe(code);
          expect(result.value.codeVerifier).toBe("test-code-verifier");
        }
      }),
      { numRuns: 200 },
    );
  });

  it("rejects with STATE_MISMATCH / HTTP 403 when the returned state does not match any stored state", () => {
    fc.assert(
      fc.property(stateArb, stateArb, codeArb, (storedState, returnedState, code) => {
        // Ensure the two state values are actually different
        fc.pre(storedState !== returnedState);

        const { validator, sessionStore } = makeContext();

        // Store one state value
        sessionStore.set(storedState, "test-code-verifier");

        // Return a different state value in the callback
        const result = handleCallback(
          { state: returnedState, code },
          "10.0.0.1",
          validator,
          sessionStore,
          silentLogger,
        );

        expect(result.ok).toBe(false);
        if (!result.ok) {
          expect(result.error.code).toBe("STATE_MISMATCH");
          expect((result.error as any).httpStatus).toBe(403);
        }
      }),
      { numRuns: 200 },
    );
  });

  it("rejects with STATE_MISMATCH / HTTP 403 when no state is stored (empty session store)", () => {
    fc.assert(
      fc.property(stateArb, codeArb, (returnedState, code) => {
        const { validator, sessionStore } = makeContext();

        // Session store is empty — no state was ever stored
        const result = handleCallback(
          { state: returnedState, code },
          "10.0.0.1",
          validator,
          sessionStore,
          silentLogger,
        );

        expect(result.ok).toBe(false);
        if (!result.ok) {
          expect(result.error.code).toBe("STATE_MISMATCH");
          expect((result.error as any).httpStatus).toBe(403);
        }
      }),
      { numRuns: 200 },
    );
  });

  it("rejects with STATE_MISMATCH when state parameter is empty string and not stored", () => {
    fc.assert(
      fc.property(codeArb, (code) => {
        const { validator, sessionStore } = makeContext();

        // Store a non-empty state, but callback returns empty string
        sessionStore.set("real-state-value", "verifier");

        const result = handleCallback(
          { state: "", code },
          "10.0.0.1",
          validator,
          sessionStore,
          silentLogger,
        );

        expect(result.ok).toBe(false);
        if (!result.ok) {
          expect(result.error.code).toBe("STATE_MISMATCH");
          expect((result.error as any).httpStatus).toBe(403);
        }
      }),
      { numRuns: 100 },
    );
  });

  it("consumes the state entry on successful match (one-time use)", () => {
    fc.assert(
      fc.property(stateArb, codeArb, (state, code) => {
        const { validator, sessionStore } = makeContext();

        sessionStore.set(state, "verifier");

        // First call succeeds
        const first = handleCallback(
          { state, code },
          "10.0.0.1",
          validator,
          sessionStore,
          silentLogger,
        );
        expect(first.ok).toBe(true);

        // Second call with the same state fails — entry was consumed
        const second = handleCallback(
          { state, code },
          "10.0.0.2", // different IP to avoid rate-limit interference
          new CallbackValidator(silentLogger, clock),
          sessionStore,
          silentLogger,
        );
        expect(second.ok).toBe(false);
        if (!second.ok) {
          expect(second.error.code).toBe("STATE_MISMATCH");
          expect((second.error as any).httpStatus).toBe(403);
        }
      }),
      { numRuns: 200 },
    );
  });
});
