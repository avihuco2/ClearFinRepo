// @clearfin/auth-service — PKCE and state generation utilities
// Generates cryptographically random state, code_verifier, and code_challenge (S256).

import { randomBytes, createHash } from "node:crypto";

export interface PKCEParams {
  state: string;
  codeVerifier: string;
  codeChallenge: string;
}

/** Generate a cryptographically random URL-safe base64 string of the given byte length. */
function randomUrlSafeBase64(byteLength: number): string {
  return randomBytes(byteLength)
    .toString("base64url");
}

/** Derive a SHA-256 code_challenge from a code_verifier (S256 method). */
export function deriveCodeChallenge(codeVerifier: string): string {
  return createHash("sha256")
    .update(codeVerifier)
    .digest("base64url");
}

/** Generate a full set of PKCE parameters: state, code_verifier, code_challenge. */
export function generatePKCEParams(): PKCEParams {
  const state = randomUrlSafeBase64(32);
  const codeVerifier = randomUrlSafeBase64(32);
  const codeChallenge = deriveCodeChallenge(codeVerifier);

  return { state, codeVerifier, codeChallenge };
}
