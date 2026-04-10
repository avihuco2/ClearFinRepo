// @clearfin/auth-service — /auth/login handler
// Constructs the Google OAuth 2.0 authorization redirect URL with PKCE.

import { type Result, ok, err } from "@clearfin/shared";
import type { Logger } from "@clearfin/shared";
import { generatePKCEParams } from "./pkce.js";
import { validateRedirectUri, type RedirectUriError } from "./redirect-uri-validator.js";
import { SessionStore } from "./session-store.js";

const GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth";

export interface LoginConfig {
  clientId: string;
  redirectUriAllowlist: ReadonlyArray<string>;
  defaultScopes: string[];
}

export interface LoginRedirect {
  redirectUrl: string;
  state: string;
}

export type LoginError = RedirectUriError;

/**
 * Build the Google OAuth 2.0 authorization redirect URL.
 *
 * 1. Validates redirect_uri against the allowlist
 * 2. Generates cryptographic state + PKCE code_verifier/code_challenge
 * 3. Stores state + code_verifier in the session store
 * 4. Constructs the full redirect URL
 */
export function buildLoginRedirect(
  redirectUri: string,
  config: LoginConfig,
  sessionStore: SessionStore,
  logger: Logger,
): Result<LoginRedirect, LoginError> {
  // Validate redirect_uri against allowlist
  const uriResult = validateRedirectUri(redirectUri, config.redirectUriAllowlist);
  if (!uriResult.ok) {
    logger.warn("Redirect URI not in allowlist", {
      attemptedUri: redirectUri,
    });
    return uriResult;
  }

  // Generate PKCE params
  const { state, codeVerifier, codeChallenge } = generatePKCEParams();

  // Store state + code_verifier for later callback validation
  sessionStore.set(state, codeVerifier);

  // Build the Google authorization URL
  const params = new URLSearchParams({
    client_id: config.clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: config.defaultScopes.join(" "),
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    access_type: "offline",
    prompt: "consent",
  });

  const redirectUrl = `${GOOGLE_AUTH_ENDPOINT}?${params.toString()}`;

  logger.info("Login redirect constructed", { state });

  return ok({ redirectUrl, state });
}
