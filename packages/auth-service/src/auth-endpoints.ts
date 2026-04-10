// @clearfin/auth-service — Auth endpoint handlers
// Thin wrappers that delegate to SessionManager for /auth/refresh and /auth/logout.

import type { Result } from "@clearfin/shared";
import type { Logger } from "@clearfin/shared";
import type { SessionManager, SessionTokens, SessionError } from "./session-manager.js";

/**
 * Handle POST /auth/refresh — rotate the refresh token and issue new session tokens.
 *
 * Requirements: 2.3
 */
export function handleRefresh(
  refreshTokenId: string,
  sessionManager: SessionManager,
  logger: Logger,
): Result<SessionTokens, SessionError> {
  logger.info("Handling refresh request", { refreshTokenId });
  return sessionManager.refreshSession(refreshTokenId);
}

/**
 * Handle POST /auth/logout — revoke the session and all associated tokens.
 *
 * Requirements: 2.7
 */
export function handleLogout(
  refreshTokenId: string,
  sessionManager: SessionManager,
  logger: Logger,
): Result<void, SessionError> {
  logger.info("Handling logout request", { refreshTokenId });
  return sessionManager.revokeSession(refreshTokenId);
}
