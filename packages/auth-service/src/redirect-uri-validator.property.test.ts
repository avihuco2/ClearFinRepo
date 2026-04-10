// Property-based tests for Redirect URI Allowlist Validation
// **Validates: Requirements 1.8**
// Property 5: Redirect URI Allowlist Validation — For any redirect_uri and
// allowlist of registered URIs, the Auth_Service SHALL accept the URI if and
// only if it exactly matches an entry in the allowlist; all non-matching URIs
// SHALL be rejected.

import { describe, it, expect } from "vitest";
import * as fc from "fast-check";
import { validateRedirectUri } from "./redirect-uri-validator.js";

/** Generator for plausible HTTPS URIs. */
const httpsUriArb = fc
  .tuple(
    fc.stringMatching(/^[a-z][a-z0-9-]{1,20}$/),
    fc.stringMatching(/^[a-z]{2,6}$/),
    fc.stringMatching(/^\/[a-z0-9/]{0,30}$/),
  )
  .map(([host, tld, path]) => `https://${host}.${tld}${path}`);

/** Generator for a non-empty allowlist of unique HTTPS URIs. */
const allowlistArb = fc.uniqueArray(httpsUriArb, { minLength: 1, maxLength: 8 });

describe("Property 5: Redirect URI Allowlist Validation", () => {
  it("accepts a URI that exactly matches an entry in the allowlist", () => {
    fc.assert(
      fc.property(
        allowlistArb.chain((allowlist) =>
          fc.tuple(
            fc.constant(allowlist),
            fc.integer({ min: 0, max: allowlist.length - 1 }),
          ),
        ),
        ([allowlist, idx]) => {
          const uri = allowlist[idx];
          const result = validateRedirectUri(uri, allowlist);

          expect(result.ok).toBe(true);
          if (result.ok) {
            expect(result.value).toBe(uri);
          }
        },
      ),
      { numRuns: 200 },
    );
  });

  it("rejects a URI that does not match any entry in the allowlist", () => {
    fc.assert(
      fc.property(
        allowlistArb,
        httpsUriArb,
        (allowlist, randomUri) => {
          fc.pre(!allowlist.includes(randomUri));

          const result = validateRedirectUri(randomUri, allowlist);

          expect(result.ok).toBe(false);
          if (!result.ok) {
            expect(result.error.code).toBe("INVALID_REDIRECT_URI");
            expect(result.error.httpStatus).toBe(403);
            expect(result.error.attemptedUri).toBe(randomUri);
          }
        },
      ),
      { numRuns: 200 },
    );
  });

  it("rejects all URIs when the allowlist is empty", () => {
    fc.assert(
      fc.property(httpsUriArb, (uri) => {
        const result = validateRedirectUri(uri, []);

        expect(result.ok).toBe(false);
        if (!result.ok) {
          expect(result.error.code).toBe("INVALID_REDIRECT_URI");
          expect(result.error.attemptedUri).toBe(uri);
        }
      }),
      { numRuns: 100 },
    );
  });

  it("rejects a URI that is a prefix of an allowlist entry", () => {
    fc.assert(
      fc.property(
        allowlistArb.chain((allowlist) =>
          fc.tuple(
            fc.constant(allowlist),
            fc.integer({ min: 0, max: allowlist.length - 1 }),
          ),
        ),
        ([allowlist, idx]) => {
          const entry = allowlist[idx];
          // Take a strict prefix (at least 8 chars for "https://", but shorter than full)
          fc.pre(entry.length > 9);
          const prefix = entry.slice(0, entry.length - 1);
          fc.pre(!allowlist.includes(prefix));

          const result = validateRedirectUri(prefix, allowlist);
          expect(result.ok).toBe(false);
        },
      ),
      { numRuns: 200 },
    );
  });

  it("rejects a URI that is a suffix extension of an allowlist entry", () => {
    fc.assert(
      fc.property(
        allowlistArb.chain((allowlist) =>
          fc.tuple(
            fc.constant(allowlist),
            fc.integer({ min: 0, max: allowlist.length - 1 }),
            fc.stringMatching(/^[a-z0-9]{1,10}$/),
          ),
        ),
        ([allowlist, idx, extra]) => {
          const entry = allowlist[idx];
          const extended = entry + extra;
          fc.pre(!allowlist.includes(extended));

          const result = validateRedirectUri(extended, allowlist);
          expect(result.ok).toBe(false);
        },
      ),
      { numRuns: 200 },
    );
  });

  it("acceptance is if-and-only-if: matches ↔ accepted, non-matches ↔ rejected", () => {
    fc.assert(
      fc.property(
        allowlistArb,
        httpsUriArb,
        (allowlist, uri) => {
          const result = validateRedirectUri(uri, allowlist);
          const isInAllowlist = allowlist.includes(uri);

          // Biconditional: accepted iff in allowlist
          expect(result.ok).toBe(isInAllowlist);
        },
      ),
      { numRuns: 200 },
    );
  });
});
