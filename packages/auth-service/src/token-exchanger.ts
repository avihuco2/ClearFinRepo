// @clearfin/auth-service — Google OAuth 2.0 token exchange
// Exchanges an authorization code + PKCE code_verifier for Google tokens
// over TLS 1.2+ to Google's token endpoint.

import { type Result, ok, err } from "@clearfin/shared";
import type { Logger } from "@clearfin/shared";

const GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";

// ── Types ────────────────────────────────────────────────────────────

export interface GoogleTokens {
  idToken: string;
  accessToken: string;
  refreshToken: string | undefined;
  tokenType: string;
  expiresIn: number;
  scope: string;
}

export interface TokenError {
  code: "TOKEN_EXCHANGE_FAILED" | "NETWORK_ERROR" | "INVALID_GRANT";
  httpStatus: 502;
  message: string;
  googleError?: string;
}

export interface TokenExchangeConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}

/**
 * Minimal HTTP client interface for POST requests.
 * Accepts dependency injection so callers can supply a real or mock client.
 */
export interface HttpClient {
  post(
    url: string,
    body: URLSearchParams,
  ): Promise<{ status: number; json(): Promise<unknown> }>;
}

// ── Default HTTP client (uses global fetch) ──────────────────────────

export const defaultHttpClient: HttpClient = {
  async post(url, body) {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    return { status: res.status, json: () => res.json() };
  },
};

// ── Token Exchanger ──────────────────────────────────────────────────

interface GoogleTokenResponse {
  id_token?: string;
  access_token?: string;
  refresh_token?: string;
  token_type?: string;
  expires_in?: number;
  scope?: string;
  error?: string;
  error_description?: string;
}

/**
 * Exchange an authorization code for Google tokens.
 *
 * Sends a POST to Google's token endpoint with:
 *   code, code_verifier, client_id, client_secret, redirect_uri, grant_type
 *
 * Returns `Result<GoogleTokens, TokenError>`.
 */
export async function exchangeToken(
  code: string,
  codeVerifier: string,
  config: TokenExchangeConfig,
  logger: Logger,
  httpClient: HttpClient = defaultHttpClient,
): Promise<Result<GoogleTokens, TokenError>> {
  const body = new URLSearchParams({
    code,
    code_verifier: codeVerifier,
    client_id: config.clientId,
    client_secret: config.clientSecret,
    redirect_uri: config.redirectUri,
    grant_type: "authorization_code",
  });

  let response: { status: number; json(): Promise<unknown> };

  try {
    response = await httpClient.post(GOOGLE_TOKEN_ENDPOINT, body);
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Unknown network error";
    logger.error("Token exchange network failure", { error: message });
    return err({
      code: "NETWORK_ERROR",
      httpStatus: 502 as const,
      message: `Network error during token exchange: ${message}`,
    });
  }

  let data: GoogleTokenResponse;
  try {
    data = (await response.json()) as GoogleTokenResponse;
  } catch {
    logger.error("Token exchange response parse failure", {
      status: response.status,
    });
    return err({
      code: "TOKEN_EXCHANGE_FAILED",
      httpStatus: 502 as const,
      message: "Failed to parse token endpoint response",
    });
  }

  // Google returns an error field on failure
  if (data.error) {
    const errorCode =
      data.error === "invalid_grant" ? "INVALID_GRANT" : "TOKEN_EXCHANGE_FAILED";

    logger.error("Google token exchange error", {
      googleError: data.error,
      googleErrorDescription: data.error_description,
      status: response.status,
    });

    return err({
      code: errorCode,
      httpStatus: 502 as const,
      message: data.error_description ?? data.error,
      googleError: data.error,
    });
  }

  // Validate required fields
  if (!data.id_token || !data.access_token) {
    logger.error("Token exchange response missing required fields", {
      hasIdToken: !!data.id_token,
      hasAccessToken: !!data.access_token,
    });
    return err({
      code: "TOKEN_EXCHANGE_FAILED",
      httpStatus: 502 as const,
      message: "Token endpoint response missing id_token or access_token",
    });
  }

  logger.info("Token exchange succeeded");

  return ok({
    idToken: data.id_token,
    accessToken: data.access_token,
    refreshToken: data.refresh_token,
    tokenType: data.token_type ?? "Bearer",
    expiresIn: data.expires_in ?? 3600,
    scope: data.scope ?? "",
  });
}
