// Unit tests for Login_Page
// Validates: Requirements 8.1, 8.2, 8.4, 8.5, 8.6

import { describe, it, expect, vi } from "vitest";
import {
  renderLoginPage,
  initiateOAuthRedirect,
  handlePostAuth,
  buildCspHeaderValue,
  buildCloudFrontResponseHeadersPolicy,
} from "./login-page.js";
import type { LoginPageConfig, PostAuthResult } from "./login-page.js";

// ── Test helpers ─────────────────────────────────────────────────────

const defaultConfig: LoginPageConfig = {
  authLoginUrl: "/auth/login",
  dashboardUrl: "/dashboard",
  appOrigin: "https://app.clearfin.io",
};

// ── 10.1: Login page rendering (Requirements 8.1, 8.3, 8.7, 8.8) ───

describe("renderLoginPage", () => {
  it("renders HTML containing the ClearFin branding", () => {
    const html = renderLoginPage(defaultConfig);
    expect(html).toContain("ClearFin");
    expect(html).toContain("app-name");
    expect(html).toContain("logo");
  });

  it('renders a "Sign in with Google" button as the sole auth method', () => {
    const html = renderLoginPage(defaultConfig);
    expect(html).toContain("Sign in with Google");
    expect(html).toContain('id="google-signin-btn"');
  });

  it("includes responsive viewport meta tag", () => {
    const html = renderLoginPage(defaultConfig);
    expect(html).toContain('name="viewport"');
    expect(html).toContain("width=device-width");
  });

  it("includes keyboard-accessible button with aria-label", () => {
    const html = renderLoginPage(defaultConfig);
    expect(html).toContain('aria-label="Sign in with Google"');
    expect(html).toContain('type="button"');
  });

  it("includes an error container with role=alert for screen readers", () => {
    const html = renderLoginPage(defaultConfig);
    expect(html).toContain('role="alert"');
    expect(html).toContain('aria-live="polite"');
    expect(html).toContain('id="error-container"');
  });

  it("includes focus-visible styles for keyboard navigation (WCAG 2.1 AA)", () => {
    const html = renderLoginPage(defaultConfig);
    expect(html).toContain("focus-visible");
  });

  it("includes the Try again button for error recovery", () => {
    const html = renderLoginPage(defaultConfig);
    expect(html).toContain('id="try-again-btn"');
    expect(html).toContain("Try again");
  });

  it("embeds the configured authLoginUrl and dashboardUrl", () => {
    const html = renderLoginPage(defaultConfig);
    expect(html).toContain("/auth/login");
    expect(html).toContain("/dashboard");
  });
});

// ── 10.2: OAuth flow initiation (Requirement 8.2) ───────────────────

describe("initiateOAuthRedirect", () => {
  it("navigates to the Auth_Service login endpoint", () => {
    const navigate = vi.fn();
    initiateOAuthRedirect(defaultConfig, navigate);
    expect(navigate).toHaveBeenCalledWith("/auth/login");
  });

  it("uses the configured authLoginUrl", () => {
    const navigate = vi.fn();
    const config: LoginPageConfig = {
      ...defaultConfig,
      authLoginUrl: "https://api.clearfin.io/auth/login",
    };
    initiateOAuthRedirect(config, navigate);
    expect(navigate).toHaveBeenCalledWith("https://api.clearfin.io/auth/login");
  });
});

// ── 10.2: Post-auth redirect handling (Requirements 8.4, 8.5) ───────

describe("handlePostAuth", () => {
  it("returns success with dashboard redirect when auth=success", () => {
    const params = new URLSearchParams("auth=success");
    const result = handlePostAuth(params, defaultConfig);
    expect(result).toEqual<PostAuthResult>({
      kind: "success",
      redirectTo: "/dashboard",
    });
  });

  it("returns error with user-friendly message when error param is present", () => {
    const params = new URLSearchParams("error=access_denied");
    const result = handlePostAuth(params, defaultConfig);
    expect(result.kind).toBe("error");
    if (result.kind === "error") {
      expect(result.message).toContain("try again");
      // Must NOT expose internal error details (Requirement 8.5)
      expect(result.message).not.toContain("access_denied");
    }
  });

  it("never exposes internal error details in the error message", () => {
    const params = new URLSearchParams("error=server_error&error_description=internal_failure_xyz");
    const result = handlePostAuth(params, defaultConfig);
    expect(result.kind).toBe("error");
    if (result.kind === "error") {
      expect(result.message).not.toContain("server_error");
      expect(result.message).not.toContain("internal_failure_xyz");
    }
  });

  it("returns idle when no auth-related params are present", () => {
    const params = new URLSearchParams("");
    const result = handlePostAuth(params, defaultConfig);
    expect(result).toEqual<PostAuthResult>({ kind: "idle" });
  });

  it("prioritises error over success when both params exist", () => {
    const params = new URLSearchParams("error=something&auth=success");
    const result = handlePostAuth(params, defaultConfig);
    expect(result.kind).toBe("error");
  });
});

// ── 10.3: CSP header configuration (Requirement 8.6) ────────────────

describe("buildCspHeaderValue", () => {
  it("restricts script-src to the application origin", () => {
    const csp = buildCspHeaderValue("https://app.clearfin.io");
    expect(csp).toContain("script-src");
    expect(csp).toContain("https://app.clearfin.io");
  });

  it("includes upgrade-insecure-requests for HTTPS enforcement", () => {
    const csp = buildCspHeaderValue("https://app.clearfin.io");
    expect(csp).toContain("upgrade-insecure-requests");
  });

  it("blocks framing with frame-ancestors 'none'", () => {
    const csp = buildCspHeaderValue("https://app.clearfin.io");
    expect(csp).toContain("frame-ancestors 'none'");
  });

  it("sets default-src to self", () => {
    const csp = buildCspHeaderValue("https://app.clearfin.io");
    expect(csp).toContain("default-src 'self'");
  });
});

describe("buildCloudFrontResponseHeadersPolicy", () => {
  it("includes CSP header configuration", () => {
    const policy = buildCloudFrontResponseHeadersPolicy("https://app.clearfin.io");
    expect(policy.contentSecurityPolicy).toBeDefined();
    expect(policy.contentSecurityPolicy.override).toBe(true);
    expect(policy.contentSecurityPolicy.contentSecurityPolicy).toContain("script-src");
  });

  it("enforces HSTS with 1-year max-age and includeSubdomains", () => {
    const policy = buildCloudFrontResponseHeadersPolicy("https://app.clearfin.io");
    expect(policy.strictTransportSecurity.accessControlMaxAgeSec).toBe(31536000);
    expect(policy.strictTransportSecurity.includeSubdomains).toBe(true);
  });

  it("sets X-Content-Type-Options", () => {
    const policy = buildCloudFrontResponseHeadersPolicy("https://app.clearfin.io");
    expect(policy.contentTypeOptions).toBeDefined();
    expect(policy.contentTypeOptions.override).toBe(true);
  });

  it("sets X-Frame-Options to DENY", () => {
    const policy = buildCloudFrontResponseHeadersPolicy("https://app.clearfin.io");
    expect(policy.frameOptions.frameOption).toBe("DENY");
  });

  it("enables HSTS preload", () => {
    const policy = buildCloudFrontResponseHeadersPolicy("https://app.clearfin.io");
    expect(policy.strictTransportSecurity.preload).toBe(true);
  });
});
