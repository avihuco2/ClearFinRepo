import { describe, it, expect, beforeEach } from "vitest";
import { handleCallback } from "./callback-handler.js";
import { CallbackValidator } from "./callback-validator.js";
import { SessionStore } from "./session-store.js";
import { createLogger } from "@clearfin/shared";

describe("handleCallback", () => {
  let validator: CallbackValidator;
  let store: SessionStore;
  let logger: ReturnType<typeof createLogger>;
  const noop = () => {};

  // Fixed clock for deterministic tests
  const fixedNow = new Date("2025-01-01T00:00:00Z");
  const clock = () => fixedNow;

  beforeEach(() => {
    logger = createLogger("auth-service-test", "test-corr-id", {}, noop);
    validator = new CallbackValidator(logger, clock);
    store = new SessionStore();
  });

  it("returns code + codeVerifier on valid callback with matching state", () => {
    store.set("abc123", "verifier_xyz");
    const result = handleCallback(
      { state: "abc123", code: "authcode42" },
      "10.0.0.1",
      validator,
      store,
      logger,
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.code).toBe("authcode42");
      expect(result.value.codeVerifier).toBe("verifier_xyz");
      expect(result.value.securityHeaders).toEqual({
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Cache-Control": "no-store",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
      });
    }
  });

  it("consumes the session entry (one-time use)", () => {
    store.set("state1", "verifier1");
    handleCallback({ state: "state1", code: "c" }, "10.0.0.1", validator, store, logger);
    expect(store.has("state1")).toBe(false);
  });

  it("rejects with STATE_MISMATCH (403) when state is not found", () => {
    const result = handleCallback(
      { state: "unknown", code: "c" },
      "10.0.0.1",
      validator,
      store,
      logger,
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("STATE_MISMATCH");
      expect((result.error as any).httpStatus).toBe(403);
    }
  });

  it("rejects with STATE_MISMATCH when state is empty string and not stored", () => {
    const result = handleCallback(
      { state: "", code: "c" },
      "10.0.0.1",
      validator,
      store,
      logger,
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("STATE_MISMATCH");
    }
  });

  it("rejects with RATE_LIMIT_EXCEEDED after 10 requests in the same window", () => {
    store.set("s", "v");
    const ip = "10.0.0.2";

    // First 10 requests succeed (rate-limit wise)
    for (let i = 0; i < 10; i++) {
      store.set(`s${i}`, "v");
      handleCallback({ state: `s${i}`, code: "c" }, ip, validator, store, logger);
    }

    // 11th request should be rate-limited
    store.set("s10", "v");
    const result = handleCallback({ state: "s10", code: "c" }, ip, validator, store, logger);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("RATE_LIMIT_EXCEEDED");
      expect((result.error as any).httpStatus).toBe(429);
    }
  });

  it("rejects with IP_BLOCKED when brute-force threshold is reached", () => {
    const ip = "10.0.0.3";

    // 5 consecutive failures (state mismatch) trigger brute-force block
    for (let i = 0; i < 5; i++) {
      handleCallback({ state: "bad", code: "c" }, ip, validator, store, logger);
    }

    // Next request should be blocked
    store.set("good", "v");
    const result = handleCallback({ state: "good", code: "c" }, ip, validator, store, logger);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("IP_BLOCKED");
      expect((result.error as any).httpStatus).toBe(429);
    }
  });

  it("rejects with INVALID_PARAMETERS for unexpected query params", () => {
    store.set("s", "v");
    const result = handleCallback(
      { state: "s", code: "c", evil: "payload" },
      "10.0.0.4",
      validator,
      store,
      logger,
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("INVALID_PARAMETERS");
      expect((result.error as any).httpStatus).toBe(400);
    }
  });

  it("rejects with INVALID_PARAMETERS when code exceeds 2048 chars", () => {
    store.set("s", "v");
    const longCode = "a".repeat(2049);
    const result = handleCallback(
      { state: "s", code: longCode },
      "10.0.0.5",
      validator,
      store,
      logger,
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("INVALID_PARAMETERS");
    }
  });

  it("records failure on state mismatch (brute-force tracking)", () => {
    const ip = "10.0.0.6";
    // 4 failures should not block
    for (let i = 0; i < 4; i++) {
      handleCallback({ state: "nope", code: "c" }, ip, validator, store, logger);
    }
    // 5th failure triggers block
    handleCallback({ state: "nope", code: "c" }, ip, validator, store, logger);

    store.set("real", "v");
    const result = handleCallback({ state: "real", code: "c" }, ip, validator, store, logger);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("IP_BLOCKED");
    }
  });

  it("resets brute-force counter on successful callback", () => {
    const ip = "10.0.0.7";
    // 3 failures
    for (let i = 0; i < 3; i++) {
      handleCallback({ state: "bad", code: "c" }, ip, validator, store, logger);
    }
    // 1 success resets counter
    store.set("ok", "v");
    const successResult = handleCallback({ state: "ok", code: "c" }, ip, validator, store, logger);
    expect(successResult.ok).toBe(true);

    // 4 more failures should not block (counter was reset)
    for (let i = 0; i < 4; i++) {
      handleCallback({ state: "bad2", code: "c" }, ip, validator, store, logger);
    }
    store.set("ok2", "v");
    const result = handleCallback({ state: "ok2", code: "c" }, ip, validator, store, logger);
    // 4 failures after reset is below threshold of 5
    expect(result.ok).toBe(true);
  });
});
