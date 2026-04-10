// @clearfin/auth-service — Callback Validator
// Validates Google OAuth 2.0 callback parameters with rate limiting,
// brute-force detection, input validation, and security headers.

import { type Result, type RateLimitEntry, ok, err } from "@clearfin/shared";
import type { Logger } from "@clearfin/shared";

// ── Error types ──────────────────────────────────────────────────────

export interface RateLimitError {
  code: "RATE_LIMIT_EXCEEDED" | "IP_BLOCKED";
  httpStatus: 429;
  sourceIp: string;
}

export interface ValidationError {
  code: "INVALID_PARAMETERS";
  httpStatus: 400;
  reasons: string[];
}

export interface BruteForceError {
  code: "IP_BLOCKED";
  httpStatus: 429;
  sourceIp: string;
}

export interface ValidatedParams {
  state: string;
  code: string;
  scope?: string;
  authuser?: string;
}

// ── Constants ────────────────────────────────────────────────────────

const RATE_LIMIT_MAX_REQUESTS = 10;
const RATE_LIMIT_WINDOW_MS = 60_000; // 60 seconds
const BRUTE_FORCE_MAX_FAILURES = 5;
const BRUTE_FORCE_WINDOW_MS = 5 * 60_000; // 5 minutes
const BRUTE_FORCE_BLOCK_MS = 15 * 60_000; // 15 minutes
const MAX_CODE_LENGTH = 2048;
const ALLOWED_QUERY_KEYS = new Set(["state", "code", "scope", "authuser"]);
const URL_SAFE_REGEX = /^[A-Za-z0-9\-._~+/=]+$/;

// ── Security Headers ─────────────────────────────────────────────────

const SECURITY_HEADERS: Record<string, string> = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Cache-Control": "no-store",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
};

// ── CallbackValidator ────────────────────────────────────────────────

export class CallbackValidator {
  /** IP → rate-limit / brute-force state */
  private entries = new Map<string, RateLimitEntry>();

  constructor(
    private readonly logger: Logger,
    /** Injectable clock for deterministic testing */
    private readonly now: () => Date = () => new Date(),
  ) {}

  // ── 2.1  Rate limiting (sliding window) ────────────────────────────

  checkRateLimit(sourceIp: string): Result<void, RateLimitError> {
    const current = this.now();
    let entry = this.entries.get(sourceIp);

    // Check if IP is currently blocked (brute-force block)
    if (entry?.blockedUntil && current < entry.blockedUntil) {
      return err({ code: "IP_BLOCKED", httpStatus: 429, sourceIp });
    }

    if (!entry || current.getTime() - entry.windowStart.getTime() >= RATE_LIMIT_WINDOW_MS) {
      // Start a new window
      entry = {
        sourceIp,
        windowStart: current,
        requestCount: 1,
        consecutiveFailures: entry?.consecutiveFailures ?? 0,
        blockedUntil: entry?.blockedUntil ?? null,
      };
      this.entries.set(sourceIp, entry);
      return ok(undefined);
    }

    entry.requestCount += 1;

    if (entry.requestCount > RATE_LIMIT_MAX_REQUESTS) {
      this.logger.warn("Rate limit exceeded", {
        sourceIp,
        requestCount: entry.requestCount,
        windowStart: entry.windowStart.toISOString(),
      });
      return err({ code: "RATE_LIMIT_EXCEEDED", httpStatus: 429, sourceIp });
    }

    return ok(undefined);
  }

  // ── 2.3  Parameter validation ──────────────────────────────────────

  validateParameters(
    queryParams: Record<string, string>,
  ): Result<ValidatedParams, ValidationError> {
    const reasons: string[] = [];

    // Check for unexpected keys
    for (const key of Object.keys(queryParams)) {
      if (!ALLOWED_QUERY_KEYS.has(key)) {
        reasons.push(`unexpected query parameter: ${key}`);
      }
    }

    const code = queryParams["code"];

    if (code !== undefined) {
      if (code.length > MAX_CODE_LENGTH) {
        reasons.push(`code exceeds ${MAX_CODE_LENGTH} characters`);
      }
      if (!URL_SAFE_REGEX.test(code)) {
        reasons.push("code contains non-URL-safe characters");
      }
    }

    if (reasons.length > 0) {
      this.logger.warn("Invalid callback parameters", {
        parameterNames: Object.keys(queryParams),
        reasons,
      });
      return err({ code: "INVALID_PARAMETERS", httpStatus: 400, reasons });
    }

    return ok({
      state: queryParams["state"] ?? "",
      code: queryParams["code"] ?? "",
      scope: queryParams["scope"],
      authuser: queryParams["authuser"],
    });
  }

  // ── 2.5  Brute-force detection ─────────────────────────────────────

  /**
   * Record a callback failure for the given IP and check whether the
   * brute-force threshold has been reached.
   */
  recordFailure(sourceIp: string): void {
    const current = this.now();
    let entry = this.entries.get(sourceIp);

    if (!entry) {
      entry = {
        sourceIp,
        windowStart: current,
        requestCount: 0,
        consecutiveFailures: 1,
        blockedUntil: null,
      };
      this.entries.set(sourceIp, entry);
      return;
    }

    // Reset consecutive failures if the brute-force window has elapsed
    const failureWindowStart = entry.windowStart;
    if (current.getTime() - failureWindowStart.getTime() >= BRUTE_FORCE_WINDOW_MS) {
      entry.consecutiveFailures = 1;
      entry.windowStart = current;
    } else {
      entry.consecutiveFailures += 1;
    }

    // Block if threshold reached
    if (entry.consecutiveFailures >= BRUTE_FORCE_MAX_FAILURES) {
      entry.blockedUntil = new Date(current.getTime() + BRUTE_FORCE_BLOCK_MS);
      this.logger.alert("Brute-force detected, IP blocked", {
        sourceIp,
        consecutiveFailures: entry.consecutiveFailures,
        blockedUntil: entry.blockedUntil.toISOString(),
      });
    }
  }

  /** Reset consecutive failure counter (call after a successful validation). */
  recordSuccess(sourceIp: string): void {
    const entry = this.entries.get(sourceIp);
    if (entry) {
      entry.consecutiveFailures = 0;
    }
  }

  checkBruteForce(sourceIp: string): Result<void, BruteForceError> {
    const current = this.now();
    const entry = this.entries.get(sourceIp);

    if (entry?.blockedUntil && current < entry.blockedUntil) {
      this.logger.warn("Blocked IP attempted callback", {
        sourceIp,
        blockedUntil: entry.blockedUntil.toISOString(),
      });
      return err({ code: "IP_BLOCKED", httpStatus: 429, sourceIp });
    }

    // Clear expired block
    if (entry?.blockedUntil && current >= entry.blockedUntil) {
      entry.blockedUntil = null;
      entry.consecutiveFailures = 0;
    }

    return ok(undefined);
  }

  // ── 2.7  Security headers ──────────────────────────────────────────

  buildSecurityHeaders(): Record<string, string> {
    return { ...SECURITY_HEADERS };
  }
}
