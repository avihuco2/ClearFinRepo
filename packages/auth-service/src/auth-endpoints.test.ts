import { describe, it, expect, beforeEach } from "vitest";
import { randomBytes } from "node:crypto";
import { createLogger } from "@clearfin/shared";
import { SessionManager } from "./session-manager.js";
import { handleRefresh, handleLogout } from "./auth-endpoints.js";

function makeSessionManager() {
  const logger = createLogger("test-auth-endpoints", "test-corr-id", {}, () => {});
  const config = {
    signingSecret: "test-secret-at-least-32-bytes-long!!",
    encryptionKey: randomBytes(32),
  };
  return { sm: new SessionManager(config, logger), logger };
}

describe("handleRefresh", () => {
  let sm: SessionManager;
  let logger: ReturnType<typeof createLogger>;

  beforeEach(() => {
    ({ sm, logger } = makeSessionManager());
  });

  it("returns new session tokens for a valid refresh token", () => {
    const session = sm.createSession({ sub: "user-1" }, "tenant-1");
    expect(session.ok).toBe(true);
    if (!session.ok) return;

    const result = handleRefresh(session.value.refreshTokenId, sm, logger);
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.value.jwt).toBeTruthy();
    expect(result.value.refreshTokenId).toBeTruthy();
    // New refresh token should differ from the original
    expect(result.value.refreshTokenId).not.toBe(session.value.refreshTokenId);
  });

  it("returns INVALID_REFRESH_TOKEN for unknown token", () => {
    const result = handleRefresh("nonexistent-token", sm, logger);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe("INVALID_REFRESH_TOKEN");
  });

  it("returns TOKEN_REPLAY_DETECTED when a consumed token is reused", () => {
    const session = sm.createSession({ sub: "user-1" }, "tenant-1");
    expect(session.ok).toBe(true);
    if (!session.ok) return;

    // First refresh consumes the token
    const first = handleRefresh(session.value.refreshTokenId, sm, logger);
    expect(first.ok).toBe(true);

    // Second refresh with the same (now consumed) token triggers replay detection
    const replay = handleRefresh(session.value.refreshTokenId, sm, logger);
    expect(replay.ok).toBe(false);
    if (replay.ok) return;
    expect(replay.error.code).toBe("TOKEN_REPLAY_DETECTED");
  });
});

describe("handleLogout", () => {
  let sm: SessionManager;
  let logger: ReturnType<typeof createLogger>;

  beforeEach(() => {
    ({ sm, logger } = makeSessionManager());
  });

  it("revokes a valid session successfully", () => {
    const session = sm.createSession({ sub: "user-1" }, "tenant-1");
    expect(session.ok).toBe(true);
    if (!session.ok) return;

    const result = handleLogout(session.value.refreshTokenId, sm, logger);
    expect(result.ok).toBe(true);

    // After logout, the refresh token should be revoked
    const token = sm.getRefreshToken(session.value.refreshTokenId);
    expect(token).toBeDefined();
    expect(token!.revokedAt).not.toBeNull();
  });

  it("returns INVALID_REFRESH_TOKEN for unknown token", () => {
    const result = handleLogout("nonexistent-token", sm, logger);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe("INVALID_REFRESH_TOKEN");
  });

  it("revokes all tokens in the family on logout", () => {
    const session = sm.createSession({ sub: "user-1" }, "tenant-1");
    expect(session.ok).toBe(true);
    if (!session.ok) return;

    // Refresh once to create a second token in the family
    const refreshed = sm.refreshSession(session.value.refreshTokenId);
    expect(refreshed.ok).toBe(true);
    if (!refreshed.ok) return;

    // Logout using the new refresh token
    const result = handleLogout(refreshed.value.refreshTokenId, sm, logger);
    expect(result.ok).toBe(true);

    // Both original and new tokens should be revoked
    const original = sm.getRefreshToken(session.value.refreshTokenId);
    const newer = sm.getRefreshToken(refreshed.value.refreshTokenId);
    expect(original!.revokedAt).not.toBeNull();
    expect(newer!.revokedAt).not.toBeNull();
  });
});
