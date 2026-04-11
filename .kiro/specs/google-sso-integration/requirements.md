# Requirements Document

## Introduction

This spec covers the operational and configuration work needed to make the existing ClearFin Google SSO authentication flow functional in production at `https://clearfin.click`. The auth-service code (PKCE, session management, callback validation, token exchange, id_token validation) already exists in `packages/auth-service/`. The login page SPA exists in `packages/login-page/` and is deployed to CloudFront. The infrastructure (ECS Fargate, ALB, CloudFront, Route 53) is deployed but the ECS services are at `desiredCount: 0`. This spec focuses on the Google Cloud Console setup, secrets provisioning, CloudFront-to-ALB routing, ECS service activation, and end-to-end verification of the OAuth flow.

## Glossary

- **Auth_Service**: The backend ECS Fargate service (`packages/auth-service/`) that handles Google SSO authentication, session management, and callback validation. Runs on port 3000 behind the ALB.
- **Login_Page**: The static SPA (`packages/login-page/`) served from S3 via CloudFront at `clearfin.click`. Displays the "Sign in with Google" button and handles post-auth redirects.
- **Google_OAuth_Client**: The OAuth 2.0 Client ID and Client Secret created in Google Cloud Console, used by Auth_Service to authenticate users via Google SSO.
- **ALB**: The Application Load Balancer deployed in the compute stack, terminating TLS and routing requests to ECS Fargate services.
- **CloudFront_Distribution**: The CloudFront distribution serving the Login_Page SPA at `clearfin.click`, configured with an S3 origin and security response headers.
- **Secrets_Manager**: AWS Secrets Manager, used to store the Google OAuth Client ID and Client Secret at runtime so they are never baked into container images.
- **Callback_URL**: The URL Google redirects to after user authentication, e.g. `https://clearfin.click/auth/callback`. Must be registered in both Google Cloud Console and the Auth_Service redirect URI allowlist.
- **ALB_Origin**: A CloudFront origin pointing to the ALB, used to route `/auth/*` requests from CloudFront to the Auth_Service ECS tasks.

## Requirements

### Requirement 1: Google OAuth 2.0 Client Registration

**User Story:** As a platform operator, I want to register a Google OAuth 2.0 Client for ClearFin, so that the Auth_Service can authenticate users via Google SSO.

#### Acceptance Criteria

1. WHEN the platform operator creates the Google_OAuth_Client in Google Cloud Console, THE Google_OAuth_Client SHALL be configured with `https://clearfin.click/auth/callback` as an authorized redirect URI.
2. WHEN the platform operator creates the Google_OAuth_Client in Google Cloud Console, THE Google_OAuth_Client SHALL be configured with `https://clearfin.click` as an authorized JavaScript origin.
3. THE Google_OAuth_Client SHALL be configured as a "Web application" type with the application name "ClearFin".

### Requirement 2: Google OAuth Secrets Provisioning

**User Story:** As a platform operator, I want the Google OAuth credentials stored securely in AWS Secrets Manager, so that the Auth_Service can retrieve them at runtime without baking secrets into container images.

#### Acceptance Criteria

1. WHEN the Google_OAuth_Client is created, THE platform operator SHALL store the Client ID and Client Secret as a JSON object in Secrets_Manager at the path `/clearfin/prod/_platform/google-oauth`.
2. THE Secrets_Manager secret at `/clearfin/prod/_platform/google-oauth` SHALL be encrypted using the per-environment KMS key (AES-256).
3. THE Auth_Service task IAM role SHALL have a policy granting `secretsmanager:GetSecretValue` permission scoped to the `/clearfin/prod/_platform/google-oauth` secret ARN.
4. WHEN the Auth_Service starts, THE Auth_Service SHALL read the Google Client ID and Client Secret from Secrets_Manager and use them to configure the login handler and token exchanger.
5. IF the Auth_Service fails to retrieve the Google OAuth secret from Secrets_Manager at startup, THEN THE Auth_Service SHALL log the failure and exit with a non-zero status code so the ECS health check marks the task as unhealthy.

### Requirement 3: CloudFront-to-ALB Routing for Auth Endpoints

**User Story:** As a platform operator, I want CloudFront to route `/auth/*` requests to the ALB, so that the Auth_Service handles OAuth login and callback requests while the Login_Page SPA continues to be served from S3.

#### Acceptance Criteria

1. THE CloudFront_Distribution SHALL have an additional origin (ALB_Origin) pointing to the ALB DNS name over HTTPS.
2. THE CloudFront_Distribution SHALL have a cache behavior for the path pattern `/auth/*` that forwards requests to the ALB_Origin with no caching (cache policy: CachingDisabled).
3. THE CloudFront_Distribution `/auth/*` behavior SHALL forward all query strings, the `Host` header, and cookies to the ALB_Origin so that OAuth state parameters and session cookies are preserved.
4. THE ALB HTTPS listener SHALL have a path-based routing rule that forwards requests matching `/auth/*` to the Auth_Service target group on port 3000.
5. THE CloudFront_Distribution SHALL use the `https-only` origin protocol policy for the ALB_Origin to ensure all CloudFront-to-ALB traffic is encrypted.

### Requirement 4: Auth_Service Runtime Configuration

**User Story:** As a platform operator, I want the Auth_Service configured with the correct production URLs and settings, so that the OAuth flow works end-to-end at `clearfin.click`.

#### Acceptance Criteria

1. THE Auth_Service SHALL be configured with `https://clearfin.click/auth/callback` as the redirect URI for Google OAuth token exchange.
2. THE Auth_Service SHALL include `https://clearfin.click/auth/callback` in the redirect URI allowlist.
3. THE Auth_Service SHALL be configured with `https://clearfin.click` as the dashboard redirect URL for post-authentication redirects.
4. THE Auth_Service SHALL be configured with `https://accounts.google.com` as the expected `iss` claim for id_token validation.
5. THE Auth_Service SHALL be configured with the Google Client ID (retrieved from Secrets_Manager) as the expected `aud` claim for id_token validation.
6. WHEN the Auth_Service receives a request on `/auth/login`, THE Auth_Service SHALL construct the Google OAuth authorization URL with the correct `client_id`, `redirect_uri`, PKCE `code_challenge`, and `state` parameter, and return an HTTP 302 redirect.
7. WHEN the Auth_Service receives a callback on `/auth/callback`, THE Auth_Service SHALL execute the full auth flow (callback validation, token exchange, id_token validation, user upsert, session creation) and redirect to the dashboard with a session cookie.

### Requirement 5: ECS Service Activation

**User Story:** As a platform operator, I want the Auth_Service ECS Fargate tasks running, so that the authentication endpoints are available to handle user login requests.

#### Acceptance Criteria

1. WHEN the Google OAuth secrets are provisioned and the CloudFront routing is configured, THE Auth_Service ECS Fargate service SHALL be scaled to a `desiredCount` of 1 (minimum).
2. WHEN the Auth_Service ECS task starts, THE ALB health check SHALL receive an HTTP 200 response from the `/health` endpoint within 60 seconds.
3. THE Auth_Service ECS task SHALL run in private subnets with no public IP assignment, communicating with Google OAuth endpoints through the NAT Gateway.
4. THE Auth_Service ECS task SHALL retrieve the Google OAuth credentials from Secrets_Manager via the VPC PrivateLink endpoint (no internet traversal for AWS service calls).

### Requirement 6: End-to-End OAuth Flow Verification

**User Story:** As a platform operator, I want to verify the complete Google SSO flow works end-to-end, so that I have confidence users can authenticate at `clearfin.click`.

#### Acceptance Criteria

1. WHEN a user navigates to `https://clearfin.click`, THE Login_Page SHALL display the "Sign in with Google" button.
2. WHEN the user clicks "Sign in with Google", THE Login_Page SHALL redirect to `https://clearfin.click/auth/login`.
3. WHEN CloudFront receives the `/auth/login` request, THE CloudFront_Distribution SHALL forward the request to the ALB_Origin, and THE Auth_Service SHALL return an HTTP 302 redirect to Google's OAuth authorization endpoint with PKCE parameters.
4. WHEN Google redirects back to `https://clearfin.click/auth/callback` with the authorization code, THE CloudFront_Distribution SHALL forward the request to the ALB_Origin, and THE Auth_Service SHALL exchange the code for tokens, validate the id_token, create a session, and redirect to the dashboard with a `Set-Cookie` header containing the session JWT.
5. IF the OAuth flow fails at any step, THEN THE Auth_Service SHALL return an appropriate HTTP error response, and THE Login_Page SHALL display a user-friendly error message with a "Try again" option.

### Requirement 7: Login Page Configuration Update

**User Story:** As a platform operator, I want the Login_Page configured with the correct Auth_Service URL, so that the "Sign in with Google" button initiates the OAuth flow through CloudFront routing.

#### Acceptance Criteria

1. THE Login_Page SHALL be built with `authLoginUrl` set to `/auth/login` so that the OAuth flow is initiated through the same CloudFront domain.
2. THE Login_Page SHALL be built with `appOrigin` set to `https://clearfin.click` for the Content-Security-Policy header.
3. THE Login_Page `connect-src` CSP directive SHALL include the CloudFront domain to allow XHR/fetch requests to `/auth/*` endpoints.
4. WHEN the Login_Page is rebuilt and deployed to S3, THE CloudFront_Distribution SHALL serve the updated `index.html` with the correct `authLoginUrl` configuration.


### Requirement 8: Login Page Professional Redesign

**User Story:** As a user visiting ClearFin for the first time, I want the login page to look polished and professional like a real fintech product, so that I trust the platform with my credentials and financial data.

#### Acceptance Criteria

1. THE Login_Page SHALL be redesigned with a distinctive, premium visual identity that conveys trust, security, and sophistication appropriate for a fintech platform.
2. THE Login_Page SHALL use distinctive typography loaded from Google Fonts (or similar CDN), avoiding generic system fonts, Inter, Roboto, Arial, or Space Grotesk.
3. THE Login_Page SHALL use a cohesive color palette with CSS custom properties, avoiding cliched schemes like plain blue buttons on white cards with gray backgrounds.
4. THE Login_Page SHALL include subtle animations and micro-interactions (page load reveals, button hover states, transitions) that create a polished, premium feel.
5. THE Login_Page SHALL use creative spatial composition and visual depth (gradients, textures, layered elements, atmospheric backgrounds) rather than a plain centered-card-on-flat-background layout.
6. THE Login_Page SHALL display the ClearFin brand identity (logo, name, tagline) with strong visual hierarchy that makes the brand memorable.
7. THE Login_Page SHALL maintain WCAG 2.1 AA contrast ratios and keyboard navigation accessibility despite the visual redesign.
8. THE Login_Page SHALL remain responsive across 320px–1920px viewport widths.
9. THE Login_Page redesign SHALL follow the frontend design steering guidelines defined in `.kiro/steering/frontend-design.md`.
