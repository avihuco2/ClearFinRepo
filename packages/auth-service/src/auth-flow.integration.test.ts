// Integration test: Full OAuth login → callback → session creation flow
// Mocks Google OAuth endpoints; validates the complete auth pipeline end-to-end.
// Requirements: 1.1–1.8, 2.1–2.7

import { describe, it, expect, beforeEach } from "vitest";
import { randomBytes, createHash, createSign, generateKeyPairSync } from "node:crypto";
import { createLogger } from "@clearfin/shared";
import { CallbackValidator } from "./callback-validator.js";
import { SessionStore } from "./session-store.js";
import { SessionManager, type SessionManagerConfig } from "./session-manager.js";
import { InMemoryUserRepository } from "./user-repository.js";
import { buildLoginRedirect, type LoginConfig } from "./login-handler.js";
import { executeAuthFlow, type AuthFlowConfig, type AuthFlowDeps } from "./auth-flow.js";
import { handleRefresh, handleLogout } from "./auth-endpoints.js";
import type { HttpClient } from "./token-exchanger.js";
import type { JwksFetcher, JWK } from "./id-token-validator.js";

// ── Helpers: build a real RSA-signed id_token ────────────────────────

const { publicKey, privateKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

function base64urlEncode(input: Buffer | string): string {
  const buf = typeof input === "string" ? Buffer.from(input) : input;
  return buf.toString("base64url");
}

function buildSignedIdToken(
  claims: Record<string, unknown>,
  kid = "test-kid-1",
): string {
  const header = { alg: "RS256", typ: "JWT", kid };
  const encodedHeader = base64urlEncode(JSON.stringify(header));
  const encodedPayload = base64urlEncode(JSON.stringify(claims));
  const signingInput = `${encodedHeader}.${encodedPayload}`;

  const sign = createSign("RSA-SHA256");
  sign.update(signingInput);
  const signature = sign.sign(privateKey);

  return `${signingInput}.${base64urlEncode(signature)}`;
}


/** Extract JWK from the test RSA public key. */
function getTestJwk(): JWK {
  const keyObj = require("node:crypto").createPublicKey(publicKey);
  const jwk = keyObj.export({ format: "jwk" });
  return {
    kty: jwk.kty,
    kid: "test-kid-1",
    n: jwk.n,
    e: jwk.e,
    alg: "RS256",
    use: "sig",
  };
}

// ── Mock factories ───────────────────────────────────────────────────

function createMockHttpClient(idToken: string): HttpClient {
  return {
    async post(_url: string, _body: URLSearchParams) {
      return {
        status: 200,
        json: async () => ({
          id_token: idToken,
          access_token: "mock-access-token",
          token_type: "Bearer",
          expires_in: 3600,
          scope: "openid email profile",
        }),
      };
    },
  };
}

function createFailingHttpClient(error: string): HttpClient {
  return {
    async post(_url: string, _body: URLSearchParams) {
      return {
        status: 400,
        json: async () => ({
          error: "invalid_grant",
          error_description: error,
        }),
      };
    },
  };
}

function createMockJwksFetcher(): JwksFetcher {
  return {
    async fetchKeys() {
      return [getTestJwk()];
    },
  };
}

const CLIENT_ID = "test-client-id.apps.googleusercontent.com";
const EXPECTED_ISS = "https://accounts.google.com";
const REDIRECT_URI = "https://app.clearfin.com/auth/callback";
const DASHBOARD_URL = "https://app.clearfin.com/dashboard";

function makeTestDeps() {
  const logger = createLogger("integration-test", "test-corr", {}, () => {});
  const sessionStore = new SessionStore();
  const callbackValidator = new CallbackValidator(logger);
  const smConfig: SessionManagerConfig = {
    signingSecret: "integration-test-secret-at-least-32-bytes!!",
    encryptionKey: randomBytes(32),
  };
  const sessionManager = new SessionManager(smConfig, logger);
  const userRepository = new InMemoryUserRepository();

  const flowConfig: AuthFlowConfig = {
    tokenExchange: {
      clientId: CLIENT_ID,
      clientSecret: "test-client-secret",
      redirectUri: REDIRECT_URI,
    },
    expectedAud: CLIENT_ID,
    expectedIss: EXPECTED_ISS,
    defaultTenantId: "tenant-001",
    dashboardUrl: DASHBOARD_URL,
    cookieName: "clearfin_session",
  };

  const loginConfig: LoginConfig = {
    clientId: CLIENT_ID,
    redirectUriAllowlist: [REDIRECT_URI],
    defaultScopes: ["openid", "email", "profile"],
  };

  return {
    logger,
    sessionStore,
    callbackValidator,
    sessionManager,
    userRepository,
    flowConfig,
    loginConfig,
  };
}

// ── Integration Tests ────────────────────────────────────────────────

describe("Auth Flow Integration: login → callback → session", () => {
  it("completes the full OAuth flow: login redirect → callback → session tokens", async () => {
    const {
      logger, sessionStore, callbackValidator,
      sessionManager, userRepository, flowConfig, loginConfig,
    } = makeTestDeps();

    // Step 1: Initiate login — build redirect URL and store state
    const loginResult = buildLoginRedirect(REDIRECT_URI, loginConfig, sessionStore, logger);
    expect(loginResult.ok).toBe(true);
    if (!loginResult.ok) return;

    const { state } = loginResult.value;
    expect(sessionStore.has(state)).toBe(true);

    // Step 2: Simulate Google callback with the state and a valid code
    const idToken = buildSignedIdToken({
      sub: "google-user-123",
      email: "user@clearfin.com",
      name: "Test User",
      aud: CLIENT_ID,
      iss: EXPECTED_ISS,
      exp: Math.floor(Date.now() / 1000) + 3600,
    });

    const deps: AuthFlowDeps = {
      callbackValidator,
      sessionStore,
      httpClient: createMockHttpClient(idToken),
      jwksFetcher: createMockJwksFetcher(),
      userRepository,
      sessionManager,
      logger,
    };

    const result = await executeAuthFlow(
      { state, code: "mock-auth-code" },
      "192.168.1.1",
      flowConfig,
      deps,
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;

    // Verify session tokens
    expect(result.value.sessionJwt).toBeTruthy();
    expect(result.value.refreshTokenId).toBeTruthy();
    expect(result.value.redirectUrl).toBe(DASHBOARD_URL);
    expect(result.value.cookieValue).toContain("clearfin_session=");
    expect(result.value.cookieValue).toContain("HttpOnly");
    expect(result.value.cookieValue).toContain("Secure");
    expect(result.value.cookieValue).toContain("SameSite=Strict");

    // Verify security headers
    expect(result.value.securityHeaders["X-Content-Type-Options"]).toBe("nosniff");
    expect(result.value.securityHeaders["X-Frame-Options"]).toBe("DENY");

    // Verify user was upserted
    expect(userRepository.users.size).toBe(1);
    const user = userRepository.users.get("google-user-123");
    expect(user).toBeDefined();
    expect(user!.email).toBe("user@clearfin.com");
    expect(user!.tenantId).toBe("tenant-001");

    // Verify state was consumed (one-time use)
    expect(sessionStore.has(state)).toBe(false);
  });

  it("rejects callback with mismatched state", async () => {
    const {
      logger, sessionStore, callbackValidator,
      sessionManager, userRepository, flowConfig, loginConfig,
    } = makeTestDeps();

    // Initiate login
    buildLoginRedirect(REDIRECT_URI, loginConfig, sessionStore, logger);

    const deps: AuthFlowDeps = {
      callbackValidator,
      sessionStore,
      httpClient: createMockHttpClient("unused"),
      jwksFetcher: createMockJwksFetcher(),
      userRepository,
      sessionManager,
      logger,
    };

    // Use a wrong state value
    const result = await executeAuthFlow(
      { state: "wrong-state-value", code: "mock-auth-code" },
      "192.168.1.1",
      flowConfig,
      deps,
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.step).toBe("callback");
  });

  it("rejects callback when token exchange fails", async () => {
    const {
      logger, sessionStore, callbackValidator,
      sessionManager, userRepository, flowConfig, loginConfig,
    } = makeTestDeps();

    const loginResult = buildLoginRedirect(REDIRECT_URI, loginConfig, sessionStore, logger);
    expect(loginResult.ok).toBe(true);
    if (!loginResult.ok) return;

    const deps: AuthFlowDeps = {
      callbackValidator,
      sessionStore,
      httpClient: createFailingHttpClient("Code already used"),
      jwksFetcher: createMockJwksFetcher(),
      userRepository,
      sessionManager,
      logger,
    };

    const result = await executeAuthFlow(
      { state: loginResult.value.state, code: "mock-auth-code" },
      "192.168.1.1",
      flowConfig,
      deps,
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.step).toBe("token_exchange");
  });

  it("rejects callback when id_token has wrong audience", async () => {
    const {
      logger, sessionStore, callbackValidator,
      sessionManager, userRepository, flowConfig, loginConfig,
    } = makeTestDeps();

    const loginResult = buildLoginRedirect(REDIRECT_URI, loginConfig, sessionStore, logger);
    expect(loginResult.ok).toBe(true);
    if (!loginResult.ok) return;

    const badIdToken = buildSignedIdToken({
      sub: "google-user-123",
      email: "user@clearfin.com",
      name: "Test User",
      aud: "wrong-client-id",
      iss: EXPECTED_ISS,
      exp: Math.floor(Date.now() / 1000) + 3600,
    });

    const deps: AuthFlowDeps = {
      callbackValidator,
      sessionStore,
      httpClient: createMockHttpClient(badIdToken),
      jwksFetcher: createMockJwksFetcher(),
      userRepository,
      sessionManager,
      logger,
    };

    const result = await executeAuthFlow(
      { state: loginResult.value.state, code: "mock-auth-code" },
      "192.168.1.1",
      flowConfig,
      deps,
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.step).toBe("id_token_validation");
  });
});

describe("Session lifecycle integration: create → refresh → logout", () => {
  it("creates session, refreshes it, then logs out — all tokens revoked", async () => {
    const {
      logger, sessionStore, callbackValidator,
      sessionManager, userRepository, flowConfig, loginConfig,
    } = makeTestDeps();

    // Full auth flow to get a session
    const loginResult = buildLoginRedirect(REDIRECT_URI, loginConfig, sessionStore, logger);
    expect(loginResult.ok).toBe(true);
    if (!loginResult.ok) return;

    const idToken = buildSignedIdToken({
      sub: "google-user-456",
      email: "lifecycle@clearfin.com",
      name: "Lifecycle User",
      aud: CLIENT_ID,
      iss: EXPECTED_ISS,
      exp: Math.floor(Date.now() / 1000) + 3600,
    });

    const deps: AuthFlowDeps = {
      callbackValidator,
      sessionStore,
      httpClient: createMockHttpClient(idToken),
      jwksFetcher: createMockJwksFetcher(),
      userRepository,
      sessionManager,
      logger,
    };

    const authResult = await executeAuthFlow(
      { state: loginResult.value.state, code: "mock-auth-code" },
      "10.0.0.1",
      flowConfig,
      deps,
    );
    expect(authResult.ok).toBe(true);
    if (!authResult.ok) return;

    // Refresh the session
    const refreshResult = handleRefresh(authResult.value.refreshTokenId, sessionManager, logger);
    expect(refreshResult.ok).toBe(true);
    if (!refreshResult.ok) return;

    expect(refreshResult.value.refreshTokenId).not.toBe(authResult.value.refreshTokenId);

    // Original refresh token should be consumed
    const originalToken = sessionManager.getRefreshToken(authResult.value.refreshTokenId);
    expect(originalToken!.consumed).toBe(true);

    // Logout using the new refresh token
    const logoutResult = handleLogout(refreshResult.value.refreshTokenId, sessionManager, logger);
    expect(logoutResult.ok).toBe(true);

    // Both tokens should be revoked
    const token1 = sessionManager.getRefreshToken(authResult.value.refreshTokenId);
    const token2 = sessionManager.getRefreshToken(refreshResult.value.refreshTokenId);
    expect(token1!.revokedAt).not.toBeNull();
    expect(token2!.revokedAt).not.toBeNull();
  });

  it("detects token replay after refresh and revokes entire family", async () => {
    const {
      logger, sessionStore, callbackValidator,
      sessionManager, userRepository, flowConfig, loginConfig,
    } = makeTestDeps();

    const loginResult = buildLoginRedirect(REDIRECT_URI, loginConfig, sessionStore, logger);
    expect(loginResult.ok).toBe(true);
    if (!loginResult.ok) return;

    const idToken = buildSignedIdToken({
      sub: "google-user-789",
      email: "replay@clearfin.com",
      name: "Replay User",
      aud: CLIENT_ID,
      iss: EXPECTED_ISS,
      exp: Math.floor(Date.now() / 1000) + 3600,
    });

    const deps: AuthFlowDeps = {
      callbackValidator,
      sessionStore,
      httpClient: createMockHttpClient(idToken),
      jwksFetcher: createMockJwksFetcher(),
      userRepository,
      sessionManager,
      logger,
    };

    const authResult = await executeAuthFlow(
      { state: loginResult.value.state, code: "mock-auth-code" },
      "10.0.0.2",
      flowConfig,
      deps,
    );
    expect(authResult.ok).toBe(true);
    if (!authResult.ok) return;

    // First refresh succeeds
    const refresh1 = handleRefresh(authResult.value.refreshTokenId, sessionManager, logger);
    expect(refresh1.ok).toBe(true);

    // Replay the original (now consumed) refresh token
    const replay = handleRefresh(authResult.value.refreshTokenId, sessionManager, logger);
    expect(replay.ok).toBe(false);
    if (replay.ok) return;
    expect(replay.error.code).toBe("TOKEN_REPLAY_DETECTED");
  });

  it("logout invalidates session within 1-second SLA", async () => {
    const {
      logger, sessionStore, callbackValidator,
      sessionManager, userRepository, flowConfig, loginConfig,
    } = makeTestDeps();

    const loginResult = buildLoginRedirect(REDIRECT_URI, loginConfig, sessionStore, logger);
    expect(loginResult.ok).toBe(true);
    if (!loginResult.ok) return;

    const idToken = buildSignedIdToken({
      sub: "google-user-sla",
      email: "sla@clearfin.com",
      name: "SLA User",
      aud: CLIENT_ID,
      iss: EXPECTED_ISS,
      exp: Math.floor(Date.now() / 1000) + 3600,
    });

    const deps: AuthFlowDeps = {
      callbackValidator,
      sessionStore,
      httpClient: createMockHttpClient(idToken),
      jwksFetcher: createMockJwksFetcher(),
      userRepository,
      sessionManager,
      logger,
    };

    const authResult = await executeAuthFlow(
      { state: loginResult.value.state, code: "mock-auth-code" },
      "10.0.0.3",
      flowConfig,
      deps,
    );
    expect(authResult.ok).toBe(true);
    if (!authResult.ok) return;

    const start = Date.now();
    const logoutResult = handleLogout(authResult.value.refreshTokenId, sessionManager, logger);
    const elapsed = Date.now() - start;

    expect(logoutResult.ok).toBe(true);
    expect(elapsed).toBeLessThan(1000); // Must complete within 1 second
  });
});
