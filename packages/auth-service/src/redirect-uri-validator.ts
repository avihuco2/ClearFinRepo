// @clearfin/auth-service — Redirect URI allowlist validation
// Validates redirect_uri against a pre-configured set of registered URIs.

import { type Result, ok, err } from "@clearfin/shared";

export interface RedirectUriError {
  code: "INVALID_REDIRECT_URI";
  httpStatus: 403;
  attemptedUri: string;
}

/**
 * Validate that a redirect_uri exactly matches one of the allowed URIs.
 * Exact string match — no wildcard or pattern support.
 */
export function validateRedirectUri(
  redirectUri: string,
  allowlist: ReadonlyArray<string>,
): Result<string, RedirectUriError> {
  if (allowlist.includes(redirectUri)) {
    return ok(redirectUri);
  }
  return err({
    code: "INVALID_REDIRECT_URI",
    httpStatus: 403,
    attemptedUri: redirectUri,
  });
}
