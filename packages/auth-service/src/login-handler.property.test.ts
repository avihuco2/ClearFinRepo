// Property-based tests for OAuth redirect URL construction
// **Validates: Requirements 1.1**
// Property 1: OAuth Redirect URL Construction — For any cryptographically random
// state value and PKCE code_verifier, the login initiation function SHALL produce
// a redirect URL that contains the `state` parameter, a `code_challenge` derived
// from the code_verifier, and a `redirect_uri` matching one of the registered URIs.

import { describe, it, expect } from "vitest";
import * as fc from "fast-check";
import { createLogger } from "@clearfin/shared";
import { buildLoginRedirect, type LoginConfig } from "./login-handler.js";
import { deriveCodeChallenge } from "./pkce.js";
import { SessionStore } from "./session-store.js";

/** Silent logger that swallows output during tests. */
const silentLogger = createLogger("test", "test-corr-id", {}, () => {});

/** Generator for plausible HTTPS URIs used as allowlist entries. */
const httpsUriArb = fc
  .tuple(
    fc.stringMatching(/^[a-z][a-z0-9-]{1,20}$/),
    fc.stringMatching(/^[a-z]{2,6}$/),
    fc.stringMatching(/^\/[a-z0-9/]{1,30}$/),
  )
  .map(([host, tld, path]) => `https://${host}.${tld}${path}`);

/** Generator for a non-empty allowlist of unique HTTPS URIs. */
const allowlistArb = fc
  .uniqueArray(httpsUriArb, { minLength: 1, maxLength: 5 })
  .filter((arr) => arr.length >= 1);

/** Generator for a LoginConfig with a random client ID and scopes. */
const loginConfigArb = (allowlist: readonly string[]) =>
  fc
    .tuple(
      fc.stringMatching(/^[a-z0-9]{8,24}\.apps\.googleusercontent\.com$/),
      fc.subarray(["openid", "email", "profile"] as const, { minLength: 1 }),
    )
    .map(
      ([clientId, scopes]): LoginConfig => ({
        clientId,
        redirectUriAllowlist: allowlist,
        defaultScopes: [...scopes],
      }),
    );

describe("Property 1: OAuth Redirect URL Construction", () => {
  it("redirect URL contains state, code_challenge (S256), and a redirect_uri from the allowlist", () => {
    fc.assert(
      fc.property(
        allowlistArb.chain((allowlist) =>
          fc.tuple(
            fc.constant(allowlist),
            loginConfigArb(allowlist),
            // Pick one URI from the allowlist as the redirect_uri
            fc.integer({ min: 0, max: allowlist.length - 1 }),
          ),
        ),
        ([allowlist, config, uriIndex]) => {
          const redirectUri = allowlist[uriIndex];
          const store = new SessionStore();

          const result = buildLoginRedirect(redirectUri, config, store, silentLogger);

          // The call must succeed for a URI in the allowlist
          expect(result.ok).toBe(true);
          if (!result.ok) return;

          const url = new URL(result.value.redirectUrl);

          // 1. state parameter is present and matches the returned state
          const urlState = url.searchParams.get("state");
          expect(urlState).toBeTruthy();
          expect(urlState).toBe(result.value.state);

          // 2. code_challenge is present and is the S256 hash of the stored code_verifier
          const urlCodeChallenge = url.searchParams.get("code_challenge");
          expect(urlCodeChallenge).toBeTruthy();
          expect(url.searchParams.get("code_challenge_method")).toBe("S256");

          // Retrieve the stored code_verifier via the session store
          const entry = store.consume(result.value.state);
          expect(entry).toBeDefined();
          const expectedChallenge = deriveCodeChallenge(entry!.codeVerifier);
          expect(urlCodeChallenge).toBe(expectedChallenge);

          // 3. redirect_uri in the URL matches the one we passed (which is in the allowlist)
          const urlRedirectUri = url.searchParams.get("redirect_uri");
          expect(urlRedirectUri).toBe(redirectUri);
          expect(config.redirectUriAllowlist).toContain(urlRedirectUri);
        },
      ),
      { numRuns: 200 },
    );
  });

  it("state stored in SessionStore matches the state in the redirect URL", () => {
    fc.assert(
      fc.property(
        allowlistArb.chain((allowlist) =>
          fc.tuple(
            fc.constant(allowlist),
            loginConfigArb(allowlist),
            fc.integer({ min: 0, max: allowlist.length - 1 }),
          ),
        ),
        ([allowlist, config, uriIndex]) => {
          const redirectUri = allowlist[uriIndex];
          const store = new SessionStore();

          const result = buildLoginRedirect(redirectUri, config, store, silentLogger);
          expect(result.ok).toBe(true);
          if (!result.ok) return;

          // The state returned by the function must exist in the store
          expect(store.has(result.value.state)).toBe(true);

          // The state in the URL must match the state in the store
          const url = new URL(result.value.redirectUrl);
          const urlState = url.searchParams.get("state")!;
          expect(store.has(urlState)).toBe(true);
          expect(urlState).toBe(result.value.state);
        },
      ),
      { numRuns: 200 },
    );
  });

  it("rejects redirect URIs not in the allowlist", () => {
    fc.assert(
      fc.property(
        allowlistArb,
        httpsUriArb,
        (allowlist, randomUri) => {
          // Only test when the random URI is NOT in the allowlist
          fc.pre(!allowlist.includes(randomUri));

          const config: LoginConfig = {
            clientId: "test-client.apps.googleusercontent.com",
            redirectUriAllowlist: allowlist,
            defaultScopes: ["openid"],
          };
          const store = new SessionStore();

          const result = buildLoginRedirect(randomUri, config, store, silentLogger);

          expect(result.ok).toBe(false);
          if (!result.ok) {
            expect(result.error.code).toBe("INVALID_REDIRECT_URI");
          }
          // No state should be stored on rejection
          expect(store.size).toBe(0);
        },
      ),
      { numRuns: 200 },
    );
  });
});
