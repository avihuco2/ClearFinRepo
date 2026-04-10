// Unit tests for CallbackValidator
// Validates: Requirements 7.1, 7.2, 7.3, 7.4, 7.5

import { describe, it, expect } from "vitest";
import { CallbackValidator } from "./callback-validator.js";
import { createLogger } from "@clearfin/shared";

const silentLogger = createLogger("test", "test-corr-id", {}, () => {});

// ── Requirement 7.1: Rate Limiting ───────────────────────────────────

describe("Rate Limiting (Req 7.1)", () => {
  it("allows the 10th request within a 60-second window", () => {
    const fixedTime = new Date("2025-01-01T00:00:00Z");
    const validator = new CallbackValidator(silentLogger, () => fixedTime);
    const ip = "192.168.1.1";

    for (let i = 0; i < 9; i++) {
      validator.checkRateLimit(ip);
    }

    const tenth = validator.checkRateLimit(ip);
    expect(tenth.ok).toBe(true);
  });

  it("rejects the 11th request within a 60-second window with HTTP 429", () => {
    const fixedTime = new Date("2025-01-01T00:00:00Z");
    const validator = new CallbackValidator(silentLogger, () => fixedTime);
    const ip = "192.168.1.1";

    for (let i = 0; i < 10; i++) {
      validator.checkRateLimit(ip);
    }

    const eleventh = validator.checkRateLimit(ip);
    expect(eleventh.ok).toBe(false);
    if (!eleventh.ok) {
      expect(eleventh.error.code).toBe("RATE_LIMIT_EXCEEDED");
      expect(eleventh.error.httpStatus).toBe(429);
      expect(eleventh.error.sourceIp).toBe(ip);
    }
  });
});

// ── Requirement 7.4: Brute-Force Detection ───────────────────────────

describe("Brute-Force Detection (Req 7.4)", () => {
  it("does NOT block after the 4th consecutive failure", () => {
    const fixedTime = new Date("2025-01-01T00:00:00Z");
    const validator = new CallbackValidator(silentLogger, () => fixedTime);
    const ip = "10.0.0.1";

    for (let i = 0; i < 4; i++) {
      validator.recordFailure(ip);
    }

    const result = validator.checkBruteForce(ip);
    expect(result.ok).toBe(true);
  });

  it("blocks after the 5th consecutive failure", () => {
    const fixedTime = new Date("2025-01-01T00:00:00Z");
    const validator = new CallbackValidator(silentLogger, () => fixedTime);
    const ip = "10.0.0.1";

    for (let i = 0; i < 5; i++) {
      validator.recordFailure(ip);
    }

    const result = validator.checkBruteForce(ip);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("IP_BLOCKED");
      expect(result.error.httpStatus).toBe(429);
      expect(result.error.sourceIp).toBe(ip);
    }
  });
});


// ── Requirements 7.2, 7.3: Code Length & Character Validation ────────

describe("Code Length Validation (Req 7.2)", () => {
  const makeValidator = () =>
    new CallbackValidator(silentLogger, () => new Date("2025-01-01T00:00:00Z"));

  it("accepts a code of exactly 2048 characters", () => {
    const code = "a".repeat(2048);
    const result = makeValidator().validateParameters({ state: "s", code });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.code).toBe(code);
    }
  });

  it("rejects a code of 2049 characters", () => {
    const code = "a".repeat(2049);
    const result = makeValidator().validateParameters({ state: "s", code });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("INVALID_PARAMETERS");
      expect(result.error.httpStatus).toBe(400);
      expect(result.error.reasons.some((r) => r.includes("2048"))).toBe(true);
    }
  });
});

describe("Non-URL-safe Character Rejection (Req 7.2)", () => {
  const makeValidator = () =>
    new CallbackValidator(silentLogger, () => new Date("2025-01-01T00:00:00Z"));

  it("rejects a code containing a space", () => {
    const result = makeValidator().validateParameters({ state: "s", code: "abc def" });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.reasons.some((r) => r.includes("non-URL-safe"))).toBe(true);
    }
  });

  it("rejects a code containing angle brackets", () => {
    const result = makeValidator().validateParameters({ state: "s", code: "abc<script>" });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.reasons.some((r) => r.includes("non-URL-safe"))).toBe(true);
    }
  });
});

// ── Requirement 7.3: Unexpected Query Parameters ─────────────────────

describe("Unexpected Query Parameters (Req 7.3)", () => {
  const makeValidator = () =>
    new CallbackValidator(silentLogger, () => new Date("2025-01-01T00:00:00Z"));

  it("rejects a request with an unexpected query parameter", () => {
    const result = makeValidator().validateParameters({
      state: "s",
      code: "validCode",
      evil: "payload",
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("INVALID_PARAMETERS");
      expect(result.error.httpStatus).toBe(400);
      expect(result.error.reasons.some((r) => r.includes("unexpected"))).toBe(true);
    }
  });

  it("accepts a request with only allowed query parameters", () => {
    const result = makeValidator().validateParameters({
      state: "s",
      code: "validCode",
      scope: "openid",
      authuser: "0",
    });
    expect(result.ok).toBe(true);
  });
});

// ── Requirement 7.5: Security Headers ────────────────────────────────

describe("Security Headers (Req 7.5)", () => {
  it("returns all required security headers with correct values", () => {
    const validator = new CallbackValidator(
      silentLogger,
      () => new Date("2025-01-01T00:00:00Z"),
    );
    const headers = validator.buildSecurityHeaders();

    expect(headers["X-Content-Type-Options"]).toBe("nosniff");
    expect(headers["X-Frame-Options"]).toBe("DENY");
    expect(headers["Cache-Control"]).toBe("no-store");
    expect(headers["Strict-Transport-Security"]).toBe(
      "max-age=31536000; includeSubDomains",
    );
  });
});
