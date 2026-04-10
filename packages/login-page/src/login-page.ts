// Login_Page — Static SPA logic for ClearFin authentication entry point
// Validates: Requirements 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7, 8.8

// ── Configuration ────────────────────────────────────────────────────

export interface LoginPageConfig {
  /** Auth_Service login endpoint URL (e.g. "/auth/login") */
  authLoginUrl: string;
  /** Dashboard URL to redirect to after successful OAuth */
  dashboardUrl: string;
  /** Application origin for CSP (e.g. "https://app.clearfin.io") */
  appOrigin: string;
}

// ── CSP Configuration (Requirement 8.6) ──────────────────────────────

/**
 * Builds the Content-Security-Policy header value restricting script
 * sources to the application's own origin. Enforces HTTPS-only.
 */
export function buildCspHeaderValue(appOrigin: string): string {
  return [
    `default-src 'self'`,
    `script-src '${appOrigin}'`,
    `style-src 'self' 'unsafe-inline'`,
    `img-src 'self' data:`,
    `connect-src 'self' ${appOrigin}`,
    `frame-ancestors 'none'`,
    `form-action 'self'`,
    `upgrade-insecure-requests`,
  ].join("; ");
}

/**
 * Returns the CloudFront response headers policy configuration object
 * for the Login_Page distribution.
 */
export function buildCloudFrontResponseHeadersPolicy(appOrigin: string) {
  return {
    contentSecurityPolicy: {
      override: true,
      contentSecurityPolicy: buildCspHeaderValue(appOrigin),
    },
    strictTransportSecurity: {
      override: true,
      accessControlMaxAgeSec: 31536000,
      includeSubdomains: true,
      preload: true,
    },
    contentTypeOptions: {
      override: true,
    },
    frameOptions: {
      override: true,
      frameOption: "DENY" as const,
    },
  };
}

// ── OAuth Flow (Requirements 8.2, 8.4, 8.5) ─────────────────────────

/**
 * Initiates the OAuth flow by navigating to the Auth_Service login endpoint.
 * In a browser context this performs `window.location.assign(...)`.
 *
 * Accepts an optional `navigate` function for testability — defaults to
 * `window.location.assign` when running in a browser.
 */
export function initiateOAuthRedirect(
  config: LoginPageConfig,
  navigate: (url: string) => void = (url) => {
    window.location.assign(url);
  },
): void {
  navigate(config.authLoginUrl);
}

/**
 * Handles post-OAuth redirect. Checks the current URL for success/error
 * indicators and returns the appropriate action.
 */
export type PostAuthResult =
  | { kind: "success"; redirectTo: string }
  | { kind: "error"; message: string }
  | { kind: "idle" };

export function handlePostAuth(
  searchParams: URLSearchParams,
  config: LoginPageConfig,
): PostAuthResult {
  const error = searchParams.get("error");
  if (error) {
    // Never expose internal error details (Requirement 8.5)
    return {
      kind: "error",
      message: "Something went wrong during sign-in. Please try again.",
    };
  }

  const authSuccess = searchParams.get("auth") === "success";
  if (authSuccess) {
    return { kind: "success", redirectTo: config.dashboardUrl };
  }

  return { kind: "idle" };
}

// ── HTML Rendering (Requirements 8.1, 8.3, 8.7, 8.8) ────────────────

/**
 * Renders the Login_Page HTML string. This is the static SPA content
 * served from S3 via CloudFront.
 *
 * - ClearFin branding (logo + app name) above the sign-in button (8.3)
 * - "Sign in with Google" as sole auth method (8.1)
 * - Responsive 320px–1920px (8.7)
 * - WCAG 2.1 AA contrast & keyboard navigation (8.8)
 */
export function renderLoginPage(config: LoginPageConfig): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>ClearFin — Sign In</title>
  <style>${getStyles()}</style>
</head>
<body>
  <main class="login-container" role="main">
    <div class="login-card">
      <div class="branding">
        <svg class="logo" aria-hidden="true" width="48" height="48" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
          <rect width="48" height="48" rx="12" fill="#1a73e8"/>
          <text x="50%" y="55%" dominant-baseline="middle" text-anchor="middle" fill="#fff" font-size="22" font-weight="bold" font-family="system-ui">CF</text>
        </svg>
        <h1 class="app-name">ClearFin</h1>
      </div>

      <button
        id="google-signin-btn"
        class="signin-btn"
        type="button"
        aria-label="Sign in with Google"
      >Sign in with Google</button>

      <div id="error-container" class="error-container" role="alert" aria-live="polite" hidden>
        <p id="error-message" class="error-message"></p>
        <button id="try-again-btn" class="try-again-btn" type="button">Try again</button>
      </div>
    </div>
  </main>
  <script>
    (function() {
      var config = {
        authLoginUrl: ${JSON.stringify(config.authLoginUrl)},
        dashboardUrl: ${JSON.stringify(config.dashboardUrl)}
      };
      var params = new URLSearchParams(window.location.search);

      // Check for post-auth state
      var error = params.get('error');
      var authSuccess = params.get('auth') === 'success';

      if (error) {
        showError('Something went wrong during sign-in. Please try again.');
      } else if (authSuccess) {
        window.location.assign(config.dashboardUrl);
      }

      document.getElementById('google-signin-btn').addEventListener('click', function() {
        window.location.assign(config.authLoginUrl);
      });

      document.getElementById('try-again-btn').addEventListener('click', function() {
        window.location.assign(config.authLoginUrl);
      });

      function showError(msg) {
        var container = document.getElementById('error-container');
        document.getElementById('error-message').textContent = msg;
        container.hidden = false;
      }
    })();
  </script>
</body>
</html>`;
}

// ── Styles (Requirements 8.7, 8.8) ──────────────────────────────────

function getStyles(): string {
  // Contrast ratios meet WCAG 2.1 AA (4.5:1 minimum for normal text)
  // #1a73e8 on white = 4.6:1, white on #1a73e8 = 4.6:1
  // #c62828 on white = 5.6:1 for error text
  return `
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #f5f5f5;
      color: #202124;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }

    .login-container {
      width: 100%;
      max-width: 420px;
      padding: 16px;
    }

    .login-card {
      background: #fff;
      border-radius: 12px;
      padding: 48px 32px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.1);
      text-align: center;
    }

    .branding { margin-bottom: 32px; }

    .logo { margin-bottom: 12px; }

    .app-name {
      font-size: 1.75rem;
      font-weight: 700;
      color: #202124;
    }

    .signin-btn {
      display: inline-block;
      width: 100%;
      padding: 12px 24px;
      font-size: 1rem;
      font-weight: 600;
      color: #fff;
      background: #1a73e8;
      border: none;
      border-radius: 8px;
      cursor: pointer;
      transition: background 0.15s;
    }

    .signin-btn:hover { background: #1557b0; }
    .signin-btn:focus-visible {
      outline: 3px solid #1a73e8;
      outline-offset: 2px;
    }

    .error-container {
      margin-top: 24px;
      padding: 16px;
      background: #fef2f2;
      border: 1px solid #fca5a5;
      border-radius: 8px;
    }

    .error-message {
      color: #c62828;
      font-size: 0.9rem;
      margin-bottom: 12px;
    }

    .try-again-btn {
      padding: 8px 20px;
      font-size: 0.875rem;
      font-weight: 600;
      color: #1a73e8;
      background: transparent;
      border: 2px solid #1a73e8;
      border-radius: 6px;
      cursor: pointer;
    }

    .try-again-btn:hover { background: #e8f0fe; }
    .try-again-btn:focus-visible {
      outline: 3px solid #1a73e8;
      outline-offset: 2px;
    }

    /* Responsive: 320px–1920px (Requirement 8.7) */
    @media (max-width: 480px) {
      .login-card { padding: 32px 20px; }
      .app-name { font-size: 1.5rem; }
    }
  `;
}
