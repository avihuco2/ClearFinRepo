// @clearfin/auth-service — Complete OAuth callback flow wiring
// Orchestrates: callback validation → token exchange → id_token validation
// → user upsert → session creation → cookie set → redirect to dashboard
//
// Requirements: 1.1–1.7, 2.1

import { type Result, ok, err } from "@clearfin/shared";
import type { Logger } from "@clearfin/shared";
import { handleCallback, type CallbackError } from "./callback-handler.js";
import { exchangeToken, type TokenError, type TokenExchangeConfig, type HttpClient } from "./token-exchanger.js";
import { validateIdToken, type IdTokenError, type JwksFetcher } from "./id-token-validator.js";
import { type UserRepository, type UserRepositoryError } from "./user-repository.js";
import { type SessionManager, type SessionError } from "./session-manager.js";
import { type CallbackValidator } from "./callback-validator.js";
import { type SessionStore } from "./session-store.js";

// ── Error types ──────────────────────────────────────────────────────

export type AuthFlowError =
  | { step: "callback"; error: CallbackError }
  | { step: "token_exchange"; error: TokenError }
  | { step: "id_token_validation"; error: IdTokenError }
  | { step: "user_upsert"; error: UserRepositoryError }
  | { step: "session_creation"; error: SessionError };

// ── Success type ─────────────────────────────────────────────────────

export interface AuthFlowResult {
  sessionJwt: string;
  refreshTokenId: string;
  securityHeaders: Record<string, string>;
  redirectUrl: string;
  cookieValue: string;
}

// ── Configuration ────────────────────────────────────────────────────

export interface AuthFlowConfig {
  tokenExchange: TokenExchangeConfig;
  expectedAud: string;
  expectedIss: string;
  defaultTenantId: string;
  dashboardUrl: string;
  cookieName: string;
}

// ── Dependencies ─────────────────────────────────────────────────────

export interface AuthFlowDeps {
  callbackValidator: CallbackValidator;
  sessionStore: SessionStore;
  httpClient?: HttpClient;
  jwksFetcher: JwksFetcher;
  userRepository: UserRepository;
  sessionManager: SessionManager;
  logger: Logger;
}

// ── Auth Flow ────────────────────────────────────────────────────────

/**
 * Execute the complete OAuth callback flow:
 *
 * 1. Validate callback parameters (rate limit, brute-force, state match)
 * 2. Exchange authorization code for Google tokens
 * 3. Validate the id_token (signature, aud, iss)
 * 4. Upsert user record from id_token claims
 * 5. Create session (JWT + refresh token)
 * 6. Build cookie and redirect to dashboard
 */
export async function executeAuthFlow(
  queryParams: Record<string, string>,
  sourceIp: string,
  config: AuthFlowConfig,
  deps: AuthFlowDeps,
): Promise<Result<AuthFlowResult, AuthFlowError>> {
  const { logger } = deps;

  // Step 1: Callback validation (rate limit, brute-force, state, params)
  const callbackResult = handleCallback(
    queryParams,
    sourceIp,
    deps.callbackValidator,
    deps.sessionStore,
    logger,
  );

  if (!callbackResult.ok) {
    return err({ step: "callback", error: callbackResult.error });
  }

  const { code, codeVerifier, securityHeaders } = callbackResult.value;

  // Step 2: Exchange authorization code for Google tokens
  const tokenResult = await exchangeToken(
    code,
    codeVerifier,
    config.tokenExchange,
    logger,
    deps.httpClient,
  );

  if (!tokenResult.ok) {
    return err({ step: "token_exchange", error: tokenResult.error });
  }

  const { idToken } = tokenResult.value;

  // Step 3: Validate id_token (signature, aud, iss)
  const idTokenResult = await validateIdToken(
    idToken,
    config.expectedAud,
    config.expectedIss,
    deps.jwksFetcher,
    logger,
  );

  if (!idTokenResult.ok) {
    return err({ step: "id_token_validation", error: idTokenResult.error });
  }

  const userClaims = idTokenResult.value;

  // Step 4: Upsert user record
  const upsertResult = await deps.userRepository.upsertUser(
    userClaims,
    config.defaultTenantId,
  );

  if (!upsertResult.ok) {
    return err({ step: "user_upsert", error: upsertResult.error });
  }

  const userRecord = upsertResult.value;

  // Step 5: Create session (JWT + refresh token)
  const sessionResult = deps.sessionManager.createSession(
    { sub: userRecord.googleSubjectId },
    userRecord.tenantId,
  );

  if (!sessionResult.ok) {
    return err({ step: "session_creation", error: sessionResult.error });
  }

  const { jwt, refreshTokenId } = sessionResult.value;

  // Step 6: Build cookie and redirect
  const cookieValue = `${config.cookieName}=${jwt}; HttpOnly; Secure; SameSite=Strict; Path=/`;

  logger.info("Auth flow completed successfully", {
    sub: userClaims.sub,
    email: userClaims.email,
    tenantId: userRecord.tenantId,
  });

  return ok({
    sessionJwt: jwt,
    refreshTokenId,
    securityHeaders,
    redirectUrl: config.dashboardUrl,
    cookieValue,
  });
}
