// @clearfin/auth-service — Google SSO authentication, session management, callback validation
export { CallbackValidator } from "./callback-validator.js";
export type {
  RateLimitError,
  ValidationError,
  BruteForceError,
  ValidatedParams,
} from "./callback-validator.js";

export { SessionStore } from "./session-store.js";
export type { SessionEntry } from "./session-store.js";

export { generatePKCEParams, deriveCodeChallenge } from "./pkce.js";
export type { PKCEParams } from "./pkce.js";

export { validateRedirectUri } from "./redirect-uri-validator.js";
export type { RedirectUriError } from "./redirect-uri-validator.js";

export { buildLoginRedirect } from "./login-handler.js";
export type { LoginConfig, LoginRedirect, LoginError } from "./login-handler.js";

export { handleCallback } from "./callback-handler.js";
export type {
  CallbackResult,
  CallbackError,
  StateMismatchError,
} from "./callback-handler.js";

export { exchangeToken, defaultHttpClient } from "./token-exchanger.js";
export type {
  GoogleTokens,
  TokenError,
  TokenExchangeConfig,
  HttpClient,
} from "./token-exchanger.js";

export { validateIdToken } from "./id-token-validator.js";
export type {
  UserClaims,
  IdTokenError,
  JWK,
  JwksFetcher,
} from "./id-token-validator.js";

export { InMemoryUserRepository } from "./user-repository.js";
export type { UserRepository, UserRepositoryError } from "./user-repository.js";

export { handleHealth } from "./health-handler.js";
export type { HealthResponse } from "./health-handler.js";

export { SessionManager } from "./session-manager.js";
export type {
  SessionTokens,
  SessionError,
  SessionManagerConfig,
  EncryptedSessionRecord,
} from "./session-manager.js";

export { handleRefresh, handleLogout } from "./auth-endpoints.js";

export { executeAuthFlow } from "./auth-flow.js";
export type {
  AuthFlowResult,
  AuthFlowError,
  AuthFlowConfig,
  AuthFlowDeps,
} from "./auth-flow.js";
