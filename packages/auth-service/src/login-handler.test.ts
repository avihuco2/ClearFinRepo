// Unit tests for /auth/login endpoint components
// Validates: Requirements 1.1, 1.8

import { describe, it, expect } from "vitest";
import { createLogger } from "@clearfin/shared";
import { generatePKCEParams, deriveCodeChallenge } from "./pkce.js";
import { validateRedirectUri } from "./redirect-uri-validator.js";
import { SessionStore } from "./session-store.js";
import { buildLoginRedirect, type LoginConfig } from "./login-handler.js";

const silentLogger = createLogger("test", "test-corr-id", {}, () => {});

// ── PKCE Generation ──────────────────────────────────────────────────

describe("PKCE Generation", () => {
  it("generates unique state values on each call", () => {
    const a = generatePKCEParams();
    const b = generatePKCEParams();
    expect(a.state).not.toBe(b.state);
  });

  it("generates unique code_verifier values on each call", () => {
    const a = generatePKCEParams();
    const b = generatePKCEParams();
    expect(a.codeVerifier).not.toBe(b.codeVerifier);
  });

  it("produces a code_challenge that is the SHA-256 of the code_verifier", () => {
    const params = generatePKCEParams();
    const expected = deriveCodeChallenge(params.codeVerifier);
    expect(params.codeChallenge).toBe(expected);
  });

  it("produces base64url-encoded values (no +, /, or = padding)", () => {
    const params = generatePKCEParams();
    const base64urlRegex = /^[A-Za-z0-9_-]+$/;
    expect(params.state).toMatch(base64urlRegex);
    expect(params.codeVerifier).toMatch(base64urlRegex);
    expect(params.codeChallenge).toMatch(base64urlRegex);
  });
});

// ── Redirect URI Validation (Req 1.8) ────────────────────────────────

describe("Redirect URI Allowlist Validation (Req 1.8)", () => {
  const allowlist = [
    "https://app.clearfin.io/auth/callback",
    "https://staging.clearfin.io/auth/callback",
  ];

  it("accepts a URI that exactly matches an allowlist entry", () => {
    const result = validateRedirectUri("https://app.clearfin.io/auth/callback", allowlist);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value).toBe("https://app.clearfin.io/auth/callback");
    }
  });

  it("rejects a URI not in the allowlist", () => {
    const result = validateRedirectUri("https://evil.com/callback", allowlist);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("INVALID_REDIRECT_URI");
      expect(result.error.httpStatus).toBe(403);
      expect(result.error.attemptedUri).toBe("https://evil.com/callback");
    }
  });

  it("rejects a URI that is a prefix of an allowlist entry", () => {
    const result = validateRedirectUri("https://app.clearfin.io/auth", allowlist);
    expect(result.ok).toBe(false);
  });

  it("rejects an empty URI", () => {
    const result = validateRedirectUri("", allowlist);
    expect(result.ok).toBe(false);
  });
});

// ── Session Store ────────────────────────────────────────────────────

describe("SessionStore", () => {
  it("stores and retrieves a state + code_verifier pair", () => {
    const store = new SessionStore();
    store.set("state-abc", "verifier-xyz");
    const entry = store.consume("state-abc");
    expect(entry).toBeDefined();
    expect(entry!.state).toBe("state-abc");
    expect(entry!.codeVerifier).toBe("verifier-xyz");
  });

  it("consumes entries (one-time use)", () => {
    const store = new SessionStore();
    store.set("state-abc", "verifier-xyz");
    store.consume("state-abc");
    const second = store.consume("state-abc");
    expect(second).toBeUndefined();
  });

  it("returns undefined for unknown state", () => {
    const store = new SessionStore();
    expect(store.consume("nonexistent")).toBeUndefined();
  });

  it("tracks size correctly", () => {
    const store = new SessionStore();
    expect(store.size).toBe(0);
    store.set("a", "v1");
    store.set("b", "v2");
    expect(store.size).toBe(2);
    store.consume("a");
    expect(store.size).toBe(1);
  });
});

// ── Login Handler (Req 1.1) ──────────────────────────────────────────

describe("buildLoginRedirect (Req 1.1)", () => {
  const config: LoginConfig = {
    clientId: "test-client-id.apps.googleusercontent.com",
    redirectUriAllowlist: [
      "https://app.clearfin.io/auth/callback",
      "https://staging.clearfin.io/auth/callback",
    ],
    defaultScopes: ["openid", "email", "profile"],
  };

  it("constructs a redirect URL pointing to Google OAuth endpoint", () => {
    const store = new SessionStore();
    const result = buildLoginRedirect(
      "https://app.clearfin.io/auth/callback",
      config,
      store,
      silentLogger,
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.redirectUrl).toContain("https://accounts.google.com/o/oauth2/v2/auth");
    }
  });

  it("includes state parameter in the redirect URL", () => {
    const store = new SessionStore();
    const result = buildLoginRedirect(
      "https://app.clearfin.io/auth/callback",
      config,
      store,
      silentLogger,
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      const url = new URL(result.value.redirectUrl);
      expect(url.searchParams.get("state")).toBe(result.value.state);
    }
  });

  it("includes code_challenge and code_challenge_method=S256", () => {
    const store = new SessionStore();
    const result = buildLoginRedirect(
      "https://app.clearfin.io/auth/callback",
      config,
      store,
      silentLogger,
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      const url = new URL(result.value.redirectUrl);
      expect(url.searchParams.get("code_challenge")).toBeTruthy();
      expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    }
  });

  it("includes the redirect_uri in the URL", () => {
    const store = new SessionStore();
    const result = buildLoginRedirect(
      "https://app.clearfin.io/auth/callback",
      config,
      store,
      silentLogger,
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      const url = new URL(result.value.redirectUrl);
      expect(url.searchParams.get("redirect_uri")).toBe("https://app.clearfin.io/auth/callback");
    }
  });

  it("stores state + code_verifier in the session store", () => {
    const store = new SessionStore();
    const result = buildLoginRedirect(
      "https://app.clearfin.io/auth/callback",
      config,
      store,
      silentLogger,
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(store.has(result.value.state)).toBe(true);
      expect(store.size).toBe(1);
    }
  });

  it("rejects a redirect_uri not in the allowlist", () => {
    const store = new SessionStore();
    const result = buildLoginRedirect(
      "https://evil.com/callback",
      config,
      store,
      silentLogger,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("INVALID_REDIRECT_URI");
      expect(result.error.httpStatus).toBe(403);
    }
  });

  it("does not store state when redirect_uri is rejected", () => {
    const store = new SessionStore();
    buildLoginRedirect(
      "https://evil.com/callback",
      config,
      store,
      silentLogger,
    );
    expect(store.size).toBe(0);
  });

  it("includes client_id in the redirect URL", () => {
    const store = new SessionStore();
    const result = buildLoginRedirect(
      "https://app.clearfin.io/auth/callback",
      config,
      store,
      silentLogger,
    );
    expect(result.ok).toBe(true);
    if (result.ok) {
      const url = new URL(result.value.redirectUrl);
      expect(url.searchParams.get("client_id")).toBe(config.clientId);
    }
  });
});
