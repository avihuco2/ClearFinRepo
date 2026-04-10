// @clearfin/auth-service — /auth/callback handler
// Processes the Google OAuth 2.0 callback: validates parameters,
// checks rate limits and brute-force, verifies state, and returns
// the authorization code + code_verifier for token exchange.

import { type Result, ok, err } from "@clearfin/shared";
import type { Logger } from "@clearfin/shared";
import {
  CallbackValidator,
  type RateLimitError,
  type ValidationError,
  type BruteForceError,
} from "./callback-validator.js";
import { SessionStore } from "./session-store.js";

// ── Error types ──────────────────────────────────────────────────────

export interface StateMismatchError {
  code: "STATE_MISMATCH";
  httpStatus: 403;
  message: string;
}

export type CallbackError =
  | RateLimitError
  | BruteForceError
  | ValidationError
  | StateMismatchError;

// ── Success type ─────────────────────────────────────────────────────

export interface CallbackResult {
  code: string;
  codeVerifier: string;
  securityHeaders: Record<string, string>;
}

// ── Handler ──────────────────────────────────────────────────────────

/**
 * Process the `/auth/callback` request.
 *
 * 1. Check rate limit via CallbackValidator
 * 2. Check brute-force block via CallbackValidator
 * 3. Validate query parameters via CallbackValidator
 * 4. Retrieve stored state + code_verifier from SessionStore
 * 5. If state doesn't match (not found), reject with HTTP 403 and log
 * 6. Return validated code + code_verifier for token exchange
 */
export function handleCallback(
  queryParams: Record<string, string>,
  sourceIp: string,
  validator: CallbackValidator,
  sessionStore: SessionStore,
  logger: Logger,
): Result<CallbackResult, CallbackError> {
  // 1. Rate limit check
  const rateResult = validator.checkRateLimit(sourceIp);
  if (!rateResult.ok) {
    validator.recordFailure(sourceIp);
    return rateResult;
  }

  // 2. Brute-force check
  const bruteResult = validator.checkBruteForce(sourceIp);
  if (!bruteResult.ok) {
    return bruteResult;
  }

  // 3. Parameter validation
  const paramResult = validator.validateParameters(queryParams);
  if (!paramResult.ok) {
    validator.recordFailure(sourceIp);
    return paramResult;
  }

  const { state, code } = paramResult.value;

  // 4 & 5. Retrieve stored state + code_verifier; reject on mismatch
  const session = sessionStore.consume(state);
  if (!session) {
    validator.recordFailure(sourceIp);
    logger.warn("State mismatch on callback", {
      sourceIp,
      returnedState: state,
    });
    return err({
      code: "STATE_MISMATCH",
      httpStatus: 403 as const,
      message: "State parameter does not match any active session",
    });
  }

  // Success — reset brute-force counter
  validator.recordSuccess(sourceIp);

  // 6. Build security headers and return result
  const securityHeaders = validator.buildSecurityHeaders();

  return ok({
    code,
    codeVerifier: session.codeVerifier,
    securityHeaders,
  });
}
