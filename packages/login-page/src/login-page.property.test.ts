// Feature: google-sso-integration, Property 1: Error messages never leak internal details
// **Validates: Requirements 6.5**
// Property 1: Error messages never leak internal details — For any error query
// parameter value (arbitrary strings, special characters, injection attempts),
// `handlePostAuth` SHALL return `kind: "error"` with the fixed generic message —
// never exposing the raw error value.

// Feature: google-sso-integration, Property 2: CSP connect-src includes the configured origin
// **Validates: Requirements 7.3**
// Property 2: CSP connect-src includes the configured origin — For any valid
// HTTPS origin string, `buildCspHeaderValue(origin)` SHALL produce a CSP header
// where the `connect-src` directive contains that exact origin string.

import { describe, it, expect } from "vitest";
import * as fc from "fast-check";
import { buildCspHeaderValue, handlePostAuth } from "./login-page.js";

const GENERIC_ERROR_MESSAGE = "Something went wrong during sign-in. Please try again.";

const stubConfig = {
  authLoginUrl: "/auth/login",
  dashboardUrl: "/dashboard",
  appOrigin: "https://app.clearfin.io",
};

describe("Property 1: Error messages never leak internal details", () => {
  it("returns the fixed generic message and never exposes the raw error value (fc.string())", () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1 }),
        (errorValue) => {
          const params = new URLSearchParams({ error: errorValue });
          const result = handlePostAuth(params, stubConfig);

          expect(result.kind).toBe("error");
          expect((result as { kind: "error"; message: string }).message).toBe(
            GENERIC_ERROR_MESSAGE,
          );

          // The raw error value must never appear in the message
          // (skip trivially short strings that are substrings of the generic message)
          if (errorValue.length >= 4 && !GENERIC_ERROR_MESSAGE.includes(errorValue)) {
            expect((result as { kind: "error"; message: string }).message).not.toContain(
              errorValue,
            );
          }
        },
      ),
      { numRuns: 100 },
    );
  });

  it("returns the fixed generic message and never exposes the raw error value (fc.unicodeString())", () => {
    fc.assert(
      fc.property(
        fc.unicodeString({ minLength: 1 }),
        (errorValue) => {
          const params = new URLSearchParams({ error: errorValue });
          const result = handlePostAuth(params, stubConfig);

          expect(result.kind).toBe("error");
          expect((result as { kind: "error"; message: string }).message).toBe(
            GENERIC_ERROR_MESSAGE,
          );

          if (errorValue.length >= 4 && !GENERIC_ERROR_MESSAGE.includes(errorValue)) {
            expect((result as { kind: "error"; message: string }).message).not.toContain(
              errorValue,
            );
          }
        },
      ),
      { numRuns: 100 },
    );
  });
});

/**
 * Generator for valid HTTPS origin strings.
 * Format: https://<hostname>[:<port>]
 * Hostname uses alphanumeric labels separated by dots.
 */
const httpsOriginArb = fc
  .tuple(
    // hostname: 1–4 labels of 1–12 lowercase alphanumeric chars
    fc.array(
      fc.stringOf(fc.constantFrom(..."abcdefghijklmnopqrstuvwxyz0123456789".split("")), {
        minLength: 1,
        maxLength: 12,
      }),
      { minLength: 1, maxLength: 4 },
    ),
    // optional port
    fc.option(fc.integer({ min: 1, max: 65535 }), { nil: undefined }),
  )
  .map(([labels, port]) => {
    const host = labels.join(".");
    return port !== undefined ? `https://${host}:${port}` : `https://${host}`;
  });

describe("Property 2: CSP connect-src includes the configured origin", () => {
  it("connect-src directive contains the exact origin for any valid HTTPS origin", () => {
    fc.assert(
      fc.property(httpsOriginArb, (origin) => {
        const csp = buildCspHeaderValue(origin);

        // Extract the connect-src directive value
        const connectSrcMatch = csp.match(/connect-src\s+([^;]+)/);
        expect(connectSrcMatch).not.toBeNull();

        const connectSrcValue = connectSrcMatch![1];
        expect(connectSrcValue).toContain(origin);
      }),
      { numRuns: 100 },
    );
  });
});
