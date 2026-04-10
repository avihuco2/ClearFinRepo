# Requirements Document

## Introduction

ClearFin Secure Foundation is Phase 1 of the ClearFin multi-tenant fintech platform, deployed in the AWS `il-central-1` (Tel Aviv) region. This phase establishes the security backbone: Google SSO authentication, AWS STS-based Just-In-Time (JIT) secret access with scoped role assumptions, and a hierarchical AWS Secrets Manager structure for multi-tenant credential isolation. All components operate under a Zero Trust model with PCI-DSS alignment and SOC2 readiness. The clearfin_sentinel agent must approve every deployment artifact before promotion.

## Glossary

- **Auth_Service**: The backend service responsible for handling Google SSO authentication flows, issuing session tokens, and managing user identity lifecycle.
- **STS_Broker**: The component that requests and manages AWS STS temporary credentials on behalf of authenticated users and services, enforcing least-privilege scoping.
- **Secrets_Hierarchy_Manager**: The component that provisions, organizes, and enforces access policies on the AWS Secrets Manager path hierarchy for both tenant-scoped secrets (`/clearfin/{env}/{tenant_id}/{secret_type}`) and platform-level general secrets (`/clearfin/{env}/_platform/{secret_type}`).
- **Session_Store**: The server-side store (backed by encrypted storage) that holds active user sessions and their associated metadata.
- **Callback_Validator**: The subcomponent of Auth_Service that validates Google OAuth 2.0 callback parameters including state, code, and redirect URI.
- **Sentinel_Gate**: The clearfin_sentinel approval checkpoint that must sign off on security-sensitive deployments and configuration changes.
- **Tenant_ID**: A unique, immutable identifier assigned to each tenant organization within ClearFin.
- **JIT_Credential**: A short-lived AWS STS temporary credential scoped to a specific tenant and action, issued just-in-time for a single operation.
- **KMS_Key**: An AWS KMS customer-managed key (AES-256) used for encryption at rest of secrets and session data.
- **Login_Page**: The frontend page served to unauthenticated users, providing the Google SSO sign-in entry point and handling post-authentication redirects.

## Requirements

### Requirement 1: Google SSO Authentication

**User Story:** As a ClearFin user, I want to authenticate via Google SSO, so that I can securely access the platform without managing a separate password.

#### Acceptance Criteria

1. WHEN a user initiates login, THE Auth_Service SHALL redirect the user to Google OAuth 2.0 authorization endpoint with a cryptographically random `state` parameter, a PKCE `code_verifier`, and the registered `redirect_uri`.
2. WHEN Google redirects back to the callback endpoint, THE Callback_Validator SHALL verify that the returned `state` parameter matches the value stored in the user's session before processing the authorization code.
3. WHEN the `state` parameter does not match or is missing, THE Callback_Validator SHALL reject the callback, log the mismatch event with the source IP, and return an HTTP 403 response.
4. WHEN a valid authorization code is received, THE Auth_Service SHALL exchange the code for tokens using the PKCE `code_verifier` over a TLS 1.2+ connection to Google's token endpoint.
5. WHEN the token exchange succeeds, THE Auth_Service SHALL validate the `id_token` signature against Google's published JWKS, verify the `aud` claim matches the registered client ID, and verify the `iss` claim matches `https://accounts.google.com`.
6. IF the `id_token` validation fails on any claim, THEN THE Auth_Service SHALL reject the authentication attempt, log the failure reason, and return an HTTP 401 response.
7. WHEN a valid `id_token` is obtained, THE Auth_Service SHALL extract the user's email, name, and Google subject ID, and create or update the user record in the platform database.
8. THE Auth_Service SHALL restrict the `redirect_uri` to a pre-configured allowlist of registered URIs and reject any callback where the `redirect_uri` does not match an entry in the allowlist.

### Requirement 2: Session Management

**User Story:** As a ClearFin user, I want my session to be securely managed, so that my authenticated state is protected against hijacking and replay attacks.

#### Acceptance Criteria

1. WHEN authentication succeeds, THE Auth_Service SHALL issue a signed session token (JWT) with an expiration time of 15 minutes and a refresh token with an expiration time of 8 hours.
2. THE Session_Store SHALL encrypt all session data at rest using the KMS_Key (AES-256).
3. WHEN a session token expires, THE Auth_Service SHALL require the client to present a valid refresh token to obtain a new session token.
4. WHEN a refresh token is used, THE Auth_Service SHALL invalidate the consumed refresh token and issue a new refresh token (rotation).
5. IF a previously invalidated refresh token is presented, THEN THE Auth_Service SHALL revoke all tokens in the token family and terminate the associated session.
6. THE Auth_Service SHALL include the Tenant_ID, user subject ID, and issued-at timestamp in every session token payload.
7. WHEN a user initiates logout, THE Auth_Service SHALL invalidate the session token and refresh token in the Session_Store within 1 second.

### Requirement 3: STS Role Assumption and JIT Credential Issuance

**User Story:** As a platform service, I want to obtain short-lived, tenant-scoped AWS credentials just-in-time, so that no long-lived credentials exist and blast radius is minimized.

#### Acceptance Criteria

1. WHEN a service requests access to a tenant's resources, THE STS_Broker SHALL call AWS STS `AssumeRole` with a session policy scoped to the requesting Tenant_ID and the specific action requested.
2. THE STS_Broker SHALL set the maximum session duration for JIT_Credentials to 900 seconds (15 minutes).
3. THE STS_Broker SHALL include the Tenant_ID and requesting service name in the `RoleSessionName` parameter of every STS `AssumeRole` call.
4. WHEN the STS `AssumeRole` call fails, THE STS_Broker SHALL log the failure with the role ARN, Tenant_ID, and error code, and return a structured error to the calling service.
5. THE STS_Broker SHALL refuse to issue a JIT_Credential when the requesting service's identity cannot be verified against the platform's service registry.
6. IF a JIT_Credential is requested for a Tenant_ID that does not exist in the platform database, THEN THE STS_Broker SHALL reject the request and log a security alert.
7. THE STS_Broker SHALL enforce that session policies attached to JIT_Credentials grant access only to Secrets Manager paths matching `/clearfin/{env}/{tenant_id}/*` for the authenticated Tenant_ID.

### Requirement 4: Secrets Manager Hierarchy Provisioning

**User Story:** As a platform operator, I want secrets organized in a strict tenant-isolated hierarchy alongside platform-level general secrets, so that cross-tenant secret access is structurally prevented and shared infrastructure credentials are centrally managed.

#### Acceptance Criteria

1. WHEN a new tenant is onboarded, THE Secrets_Hierarchy_Manager SHALL create the secret path structure `/clearfin/{env}/{tenant_id}/bank-credentials`, `/clearfin/{env}/{tenant_id}/api-keys`, and `/clearfin/{env}/{tenant_id}/config`.
2. THE Secrets_Hierarchy_Manager SHALL apply a resource policy to each tenant-scoped secret that restricts access to IAM principals with a matching `aws:PrincipalTag/tenant_id` condition.
3. THE Secrets_Hierarchy_Manager SHALL encrypt all secrets using a per-environment KMS_Key with AES-256 encryption.
4. WHEN a secret is created or updated, THE Secrets_Hierarchy_Manager SHALL enable automatic rotation with a rotation interval of 90 days.
5. IF a request attempts to access a secret path where the Tenant_ID in the path does not match the Tenant_ID in the caller's session policy, THEN THE Secrets_Hierarchy_Manager SHALL deny the request and log a cross-tenant access violation.
6. THE Secrets_Hierarchy_Manager SHALL tag every secret with `tenant_id` (or `_platform` for general secrets), `environment`, `secret_type`, and `created_by` metadata tags.
7. WHEN the platform environment is initialized, THE Secrets_Hierarchy_Manager SHALL create the platform-level secret path structure `/clearfin/{env}/_platform/database-credentials`, `/clearfin/{env}/_platform/ai-api-keys`, and `/clearfin/{env}/_platform/service-config`.
8. THE Secrets_Hierarchy_Manager SHALL apply a resource policy to each platform-level secret that restricts access exclusively to IAM roles designated as platform service roles (e.g., Auth_Service, STS_Broker) and denies access to tenant-scoped JIT_Credentials.
9. THE Secrets_Hierarchy_Manager SHALL store the Aurora database connection credentials (host, port, username, password, database name) under `/clearfin/{env}/_platform/database-credentials` and enforce rotation with a maximum interval of 90 days.
10. THE Secrets_Hierarchy_Manager SHALL store external AI service API keys (e.g., Google AI Studio) under `/clearfin/{env}/_platform/ai-api-keys` and enforce rotation with a maximum interval of 90 days.

### Requirement 5: Sentinel Approval Gate

**User Story:** As a security auditor (clearfin_sentinel), I want to approve all security-sensitive deployments, so that no unauthorized infrastructure changes reach production.

#### Acceptance Criteria

1. WHEN a deployment artifact is produced for the Secure Foundation components, THE Sentinel_Gate SHALL block promotion to the target environment until clearfin_sentinel provides an explicit approval.
2. THE Sentinel_Gate SHALL validate that the deployment artifact includes IAM policy documents, STS trust policies, and Secrets Manager resource policies before requesting approval.
3. WHEN clearfin_sentinel rejects a deployment, THE Sentinel_Gate SHALL log the rejection reason, notify the deployment initiator, and halt the pipeline.
4. IF a deployment bypasses the Sentinel_Gate, THEN THE Sentinel_Gate SHALL trigger a kill-switch that revokes the deployed resources' IAM permissions and raises a critical alert.
5. THE Sentinel_Gate SHALL record every approval and rejection decision with a timestamp, the artifact hash, and the approver identity in an immutable audit log.

### Requirement 6: Infrastructure Security Baseline

**User Story:** As a platform operator, I want the foundational infrastructure to enforce Zero Trust networking and encryption, so that the platform meets PCI-DSS and SOC2 requirements from day one.

#### Acceptance Criteria

1. THE Auth_Service SHALL run on AWS Fargate tasks deployed exclusively in private subnets with no public IP assignment.
2. THE Auth_Service SHALL communicate with external identity providers (Google) only through a NAT Gateway; all traffic to AWS services (STS, Secrets Manager, KMS, ECR, CloudWatch) SHALL use VPC PrivateLink endpoints to avoid traversing the public internet.
3. THE Auth_Service SHALL enforce TLS 1.2 as the minimum protocol version for all inbound and outbound connections.
4. WHEN CloudTrail detects an API call that modifies IAM policies, STS trust relationships, or Secrets Manager resource policies, THE Sentinel_Gate SHALL generate a security audit event within 60 seconds.
5. THE Secrets_Hierarchy_Manager SHALL log all secret access events (read, write, rotate) to CloudTrail with the caller's Tenant_ID and session name.
6. THE Auth_Service SHALL expose a `/health` endpoint that returns the service status without requiring authentication, for use by load balancer health checks.

### Requirement 7: Callback Endpoint Hardening

**User Story:** As a security engineer, I want the Google SSO callback endpoint to be resilient against common web attacks, so that the authentication flow cannot be exploited.

#### Acceptance Criteria

1. THE Callback_Validator SHALL enforce a maximum of 10 callback requests per source IP address within a 60-second window and return HTTP 429 for excess requests.
2. WHEN a callback request is received, THE Callback_Validator SHALL validate that the `code` parameter length does not exceed 2048 characters and contains only URL-safe characters.
3. THE Callback_Validator SHALL reject callback requests that contain unexpected query parameters beyond `state`, `code`, `scope`, and `authuser`.
4. WHEN 5 consecutive failed callback validations occur from the same source IP within 5 minutes, THE Callback_Validator SHALL temporarily block that IP for 15 minutes and log a brute-force alert.
5. THE Callback_Validator SHALL set the following HTTP response headers on all callback responses: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store`, and `Strict-Transport-Security: max-age=31536000; includeSubDomains`.

### Requirement 8: Login Page

**User Story:** As a ClearFin user, I want a login page that allows me to sign in with Google, so that I have a clear and secure entry point to the platform.

#### Acceptance Criteria

1. WHEN an unauthenticated user navigates to the application, THE Login_Page SHALL display a "Sign in with Google" button as the sole authentication method.
2. WHEN the user clicks the "Sign in with Google" button, THE Login_Page SHALL initiate the OAuth flow by redirecting to the Auth_Service `/auth/login` endpoint.
3. THE Login_Page SHALL display the ClearFin branding (logo and application name) above the sign-in button.
4. WHEN the OAuth flow completes successfully, THE Login_Page SHALL redirect the user to the application dashboard.
5. WHEN the OAuth flow fails, THE Login_Page SHALL display a user-friendly error message without exposing internal error details and offer a "Try again" option.
6. THE Login_Page SHALL be served over HTTPS and set `Content-Security-Policy` headers that restrict script sources to the application's own origin.
7. THE Login_Page SHALL be responsive and render correctly on viewport widths from 320px to 1920px.
8. THE Login_Page SHALL meet WCAG 2.1 Level AA contrast and keyboard navigation requirements for the sign-in button and error messages.
