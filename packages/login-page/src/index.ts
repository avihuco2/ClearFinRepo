// @clearfin/login-page — static SPA with "Sign in with Google" button
export {
  buildCspHeaderValue,
  buildCloudFrontResponseHeadersPolicy,
  initiateOAuthRedirect,
  handlePostAuth,
  renderLoginPage,
} from "./login-page.js";

export type {
  LoginPageConfig,
  PostAuthResult,
} from "./login-page.js";
