# Implementation Plan: ClearFin Secure Foundation (Phase 1)

## Overview

Incremental implementation of the ClearFin security backbone in TypeScript. Each task builds on the previous, starting with shared types and utilities, then implementing each service (Auth_Service, STS_Broker, Secrets_Hierarchy_Manager, Sentinel_Gate), the Login_Page SPA, and finally the infrastructure (IaC) wiring. Property-based tests use `fast-check`.

## Tasks

- [x] 1. Set up project structure, shared types, and core utilities
  - [x] 1.1 Create monorepo directory structure with packages for `auth-service`, `sts-broker`, `secrets-hierarchy-manager`, `sentinel-gate`, `login-page`, `shared`, and `infra`
    - Initialize `tsconfig.json`, `package.json` per package
    - Install shared dependencies: `fast-check`, `jest` (or `vitest`), `typescript`
    - _Requirements: All_

  - [x] 1.2 Define shared TypeScript interfaces and types in `shared` package
    - `UserRecord`, `SessionTokenPayload`, `RefreshTokenRecord`, `JITCredential`, `STSSessionPolicy`, `SecretTags`, `SentinelAuditRecord`, `RateLimitEntry`
    - Define `Result<T, E>` utility type for all service return types
    - _Requirements: 1.7, 2.1, 2.6, 3.1, 3.3, 4.6, 5.5, 7.1_

  - [x] 1.3 Implement structured logging utility
    - JSON-structured log output with correlation IDs, severity levels (INFO, WARN, ERROR, CRITICAL, ALERT)
    - _Requirements: 6.5, 7.4_


- [x] 2. Implement Callback Validator (Auth_Service subcomponent)
  - [x] 2.1 Implement `CallbackValidator.checkRateLimit(sourceIp)` with sliding-window rate limiting
    - 10 requests per 60-second window per source IP; return HTTP 429 on excess
    - Implement `RateLimitEntry` state management
    - _Requirements: 7.1_

  - [x] 2.2 Write property test for rate limiting
    - **Property 19: Callback Rate Limiting**
    - **Validates: Requirements 7.1**

  - [x] 2.3 Implement `CallbackValidator.validateParameters(queryParams)` with input validation
    - Reject `code` exceeding 2048 characters or containing non-URL-safe characters
    - Reject unexpected query parameters beyond `{state, code, scope, authuser}`
    - _Requirements: 7.2, 7.3_

  - [x] 2.4 Write property test for callback input validation
    - **Property 20: Callback Input Validation**
    - **Validates: Requirements 7.2, 7.3**

  - [x] 2.5 Implement `CallbackValidator.checkBruteForce(sourceIp)` with consecutive failure tracking
    - 5 consecutive failures within 5 minutes triggers 15-minute IP block and brute-force alert log
    - _Requirements: 7.4_

  - [x] 2.6 Write property test for brute-force detection
    - **Property 21: Brute-Force Detection and Blocking**
    - **Validates: Requirements 7.4**

  - [x] 2.7 Implement `CallbackValidator.buildSecurityHeaders()` returning hardened HTTP headers
    - `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Cache-Control: no-store`, `Strict-Transport-Security: max-age=31536000; includeSubDomains`
    - _Requirements: 7.5_

  - [x] 2.8 Write unit tests for Callback Validator
    - Rate limit boundary (10th and 11th request), brute-force boundary (4th and 5th failure), code length edge cases (2048, 2049), security header presence
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5_

- [x] 3. Implement Auth_Service OAuth flow
  - [x] 3.1 Implement `/auth/login` endpoint — OAuth redirect construction
    - Generate cryptographically random `state`, PKCE `code_verifier` and `code_challenge`
    - Store `state` + `code_verifier` in Session_Store keyed by state
    - Redirect to Google OAuth 2.0 authorization endpoint with `state`, `code_challenge`, `redirect_uri`
    - Validate `redirect_uri` against pre-configured allowlist
    - _Requirements: 1.1, 1.8_

  - [x] 3.2 Write property test for OAuth redirect URL construction
    - **Property 1: OAuth Redirect URL Construction**
    - **Validates: Requirements 1.1**

  - [x] 3.3 Write property test for redirect URI allowlist validation
    - **Property 5: Redirect URI Allowlist Validation**
    - **Validates: Requirements 1.8**

  - [x] 3.4 Implement `/auth/callback` endpoint — callback processing
    - Integrate `CallbackValidator` for rate limiting, parameter validation, brute-force checks
    - Retrieve stored `state` + `code_verifier` from Session_Store
    - Validate returned `state` matches stored value; reject with HTTP 403 and log on mismatch
    - _Requirements: 1.2, 1.3, 7.1, 7.2, 7.3, 7.4, 7.5_

  - [x] 3.5 Write property test for state parameter matching
    - **Property 2: State Parameter Matching**
    - **Validates: Requirements 1.2, 1.3**

  - [x] 3.6 Implement `TokenExchanger.exchange(code, codeVerifier)` — Google token exchange
    - Exchange authorization code for tokens over TLS 1.2+ to Google's token endpoint
    - _Requirements: 1.4_

  - [x] 3.7 Implement `IdTokenValidator.validate(idToken, expectedAud, expectedIss)` — id_token validation
    - Validate signature against Google JWKS, verify `aud` matches client ID, verify `iss` matches `https://accounts.google.com`
    - Reject and log with HTTP 401 on any claim failure
    - _Requirements: 1.5, 1.6_

  - [x] 3.8 Write property test for id_token claim validation
    - **Property 3: id_token Claim Validation**
    - **Validates: Requirements 1.5, 1.6**

  - [x] 3.9 Implement user info extraction and upsert
    - Extract email, name, Google subject ID from valid id_token
    - Create or update `UserRecord` in Aurora database
    - _Requirements: 1.7_

  - [x] 3.10 Write property test for user info extraction
    - **Property 4: User Info Extraction from id_token**
    - **Validates: Requirements 1.7**

  - [x] 3.11 Implement `/health` endpoint
    - Return service status without authentication for ALB health checks
    - _Requirements: 6.6_

  - [x] 3.12 Write unit tests for Auth_Service OAuth flow
    - Login redirect construction, callback validation (valid/invalid state, missing params), id_token validation with known-good and known-bad tokens, user record extraction, redirect URI allowlist matching
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8_


- [x] 4. Implement Session Management
  - [x] 4.1 Implement `SessionManager.createSession(userClaims, tenantId)` — JWT + refresh token issuance
    - Sign session JWT with `sub`, `tenantId`, `iat`, `exp` (iat + 15 min), `jti`, `tokenFamily`
    - Issue refresh token with 8-hour expiration, linked to token family
    - Encrypt session data at rest using KMS_Key (AES-256) in Session_Store
    - _Requirements: 2.1, 2.2, 2.6_

  - [x] 4.2 Write property test for session token construction
    - **Property 6: Session Token Construction**
    - **Validates: Requirements 2.1, 2.6**

  - [x] 4.3 Implement `SessionManager.refreshSession(refreshToken)` — token rotation
    - Validate refresh token, mark as consumed, issue new refresh token with same token family
    - If consumed refresh token is presented, revoke entire token family and terminate session
    - _Requirements: 2.3, 2.4, 2.5_

  - [x] 4.4 Write property test for refresh token rotation
    - **Property 7: Refresh Token Rotation**
    - **Validates: Requirements 2.4**

  - [x] 4.5 Write property test for token family revocation on replay
    - **Property 8: Token Family Revocation on Replay**
    - **Validates: Requirements 2.5**

  - [x] 4.6 Implement `SessionManager.revokeSession(sessionId)` — logout
    - Invalidate session token and refresh token in Session_Store within 1 second
    - _Requirements: 2.7_

  - [x] 4.7 Implement `/auth/refresh` and `/auth/logout` endpoints
    - Wire `SessionManager.refreshSession` to POST `/auth/refresh`
    - Wire `SessionManager.revokeSession` to POST `/auth/logout`
    - _Requirements: 2.3, 2.7_

  - [x] 4.8 Write unit tests for session management
    - JWT creation with known timestamps, refresh token rotation with specific token IDs, token family revocation with a 3-rotation chain, logout invalidation within 1 second
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7_

- [x] 5. Checkpoint — Auth_Service and Session Management
  - Ensure all tests pass, ask the user if questions arise.

- [x] 6. Implement STS_Broker
  - [x] 6.1 Implement `STSBroker.buildSessionPolicy(tenantId, action)` — session policy construction
    - Build IAM session policy with `Resource` scoped to `arn:aws:secretsmanager:*:*:secret:/clearfin/{env}/{tenantId}/*`
    - _Requirements: 3.1, 3.7_

  - [x] 6.2 Write property test for STS request construction
    - **Property 9: STS Request Construction**
    - **Validates: Requirements 3.1, 3.3, 3.7**

  - [x] 6.3 Implement `STSBroker.buildRoleSessionName(tenantId, serviceName)` — session name formatting
    - Format: `{tenantId}-{serviceName}`
    - _Requirements: 3.3_

  - [x] 6.4 Implement service identity verification against platform service registry
    - Reject unregistered service names with `SERVICE_NOT_REGISTERED` error
    - _Requirements: 3.5_

  - [x] 6.5 Write property test for service identity verification
    - **Property 10: Service Identity Verification**
    - **Validates: Requirements 3.5**

  - [x] 6.6 Implement tenant existence validation
    - Reject non-existent tenant IDs with `TENANT_NOT_FOUND` error and security alert log
    - _Requirements: 3.6_

  - [x] 6.7 Write property test for non-existent tenant rejection
    - **Property 11: Non-Existent Tenant Rejection**
    - **Validates: Requirements 3.6**

  - [x] 6.8 Implement `STSBroker.issueCredential(tenantId, serviceName, action)` — full JIT credential flow
    - Verify service identity, validate tenant exists, build session policy, call AWS STS `AssumeRole` with 900-second max duration
    - Log failures with role ARN, tenant_id, and error code
    - Return structured `JITCredential` or error
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7_

  - [x] 6.9 Write unit tests for STS_Broker
    - Session policy construction for specific tenant/action pairs, RoleSessionName formatting, service registry lookup (registered/unregistered), tenant existence check, AssumeRole failure handling
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7_


- [x] 7. Implement Secrets_Hierarchy_Manager
  - [x] 7.1 Implement `SecretsHierarchyManager.provisionTenant(tenantId, env)` — tenant secret path creation
    - Create `/clearfin/{env}/{tenant_id}/bank-credentials`, `/clearfin/{env}/{tenant_id}/api-keys`, `/clearfin/{env}/{tenant_id}/config`
    - _Requirements: 4.1_

  - [x] 7.2 Write property test for secret path construction
    - **Property 12: Secret Path Construction**
    - **Validates: Requirements 4.1, 4.7**

  - [x] 7.3 Implement `SecretsHierarchyManager.applyResourcePolicy(secretArn, policyDocument)` — tenant resource policies
    - Apply resource policy with `aws:PrincipalTag/tenant_id` condition matching only the specified tenant_id
    - _Requirements: 4.2_

  - [x] 7.4 Write property test for tenant resource policy construction
    - **Property 13: Tenant Resource Policy Construction**
    - **Validates: Requirements 4.2**

  - [x] 7.5 Implement cross-tenant access denial logic
    - Deny requests where path tenant_id differs from caller's session tenant_id; log CRITICAL cross-tenant access violation
    - _Requirements: 4.5_

  - [x] 7.6 Write property test for cross-tenant access denial
    - **Property 14: Cross-Tenant Access Denial**
    - **Validates: Requirements 4.5**

  - [x] 7.7 Implement `SecretsHierarchyManager.enableRotation(secretArn, intervalDays)` — rotation configuration
    - Enable automatic rotation with 90-day interval
    - Encrypt all secrets using per-environment KMS_Key (AES-256)
    - _Requirements: 4.3, 4.4_

  - [x] 7.8 Implement `SecretsHierarchyManager.tagSecret(secretArn, tags)` — metadata tagging
    - Tag every secret with `tenant_id` (or `_platform`), `environment`, `secret_type`, `created_by`
    - _Requirements: 4.6_

  - [x] 7.9 Write property test for secret metadata tagging
    - **Property 15: Secret Metadata Tagging**
    - **Validates: Requirements 4.6**

  - [x] 7.10 Implement `SecretsHierarchyManager.provisionPlatformSecrets(env)` — platform-level secrets
    - Create `/clearfin/{env}/_platform/database-credentials`, `/clearfin/{env}/_platform/ai-api-keys`, `/clearfin/{env}/_platform/service-config`
    - Store Aurora DB connection credentials under `database-credentials`, AI API keys under `ai-api-keys`
    - Apply resource policy restricting access to platform service roles and denying tenant-scoped JIT_Credentials
    - _Requirements: 4.7, 4.8, 4.9, 4.10_

  - [x] 7.11 Write property test for platform resource policy construction
    - **Property 16: Platform Resource Policy Construction**
    - **Validates: Requirements 4.8**

  - [x] 7.12 Write unit tests for Secrets_Hierarchy_Manager
    - Path construction for specific tenant IDs and environments, resource policy generation for tenant and platform secrets, tag construction, cross-tenant access denial with specific tenant pairs
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 4.9, 4.10_

- [x] 8. Checkpoint — STS_Broker and Secrets_Hierarchy_Manager
  - Ensure all tests pass, ask the user if questions arise.

- [x] 9. Implement Sentinel_Gate
  - [x] 9.1 Implement `SentinelGate.validateArtifact(artifact)` — deployment artifact validation
    - Verify artifact contains IAM policy documents, STS trust policies, and Secrets Manager resource policies
    - Reject incomplete artifacts with list of missing components
    - _Requirements: 5.2_

  - [x] 9.2 Write property test for deployment artifact validation
    - **Property 17: Deployment Artifact Validation**
    - **Validates: Requirements 5.2**

  - [x] 9.3 Implement `SentinelGate.submitForApproval(artifact)` — approval submission
    - Block promotion until clearfin_sentinel provides explicit approval
    - _Requirements: 5.1_

  - [x] 9.4 Implement `SentinelGate.recordDecision(approvalId, decision, approverIdentity)` — audit logging
    - Record timestamp, SHA-256 artifact hash, approver identity in immutable audit log
    - Log rejection reason and notify deployment initiator on rejection; halt pipeline
    - _Requirements: 5.3, 5.5_

  - [x] 9.5 Write property test for audit record construction
    - **Property 18: Audit Record Construction**
    - **Validates: Requirements 5.5**

  - [x] 9.6 Implement `SentinelGate.triggerKillSwitch(deploymentId)` — bypass detection
    - Revoke deployed resources' IAM permissions and raise CRITICAL alert on bypass detection
    - _Requirements: 5.4_

  - [x] 9.7 Implement CloudTrail event monitoring integration
    - Detect API calls modifying IAM policies, STS trust relationships, or Secrets Manager resource policies
    - Generate security audit event within 60 seconds of detection
    - _Requirements: 6.4_

  - [x] 9.8 Write unit tests for Sentinel_Gate
    - Artifact validation with complete/incomplete artifacts, audit record creation for approval/rejection, kill-switch trigger
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 6.4_


- [x] 10. Implement Login_Page SPA
  - [x] 10.1 Create Login_Page static SPA with ClearFin branding and "Sign in with Google" button
    - Display ClearFin logo and application name above the sign-in button
    - "Sign in with Google" button as the sole authentication method
    - Responsive layout supporting 320px–1920px viewports
    - Keyboard navigable with WCAG 2.1 Level AA contrast ratios
    - _Requirements: 8.1, 8.3, 8.7, 8.8_

  - [x] 10.2 Implement OAuth flow initiation and post-auth redirect handling
    - On button click, redirect to Auth_Service `/auth/login` endpoint
    - On successful OAuth completion, redirect to application dashboard
    - On OAuth failure, display user-friendly error message (no internal details) with "Try again" option
    - _Requirements: 8.2, 8.4, 8.5_

  - [x] 10.3 Configure `Content-Security-Policy` headers restricting script sources to application origin
    - Set CSP header via CloudFront response headers policy configuration
    - Serve over HTTPS only
    - _Requirements: 8.6_

  - [x] 10.4 Write unit tests for Login_Page
    - Verify button renders, OAuth redirect triggers, error message display, CSP header presence
    - _Requirements: 8.1, 8.2, 8.4, 8.5, 8.6_

- [x] 11. Checkpoint — Sentinel_Gate and Login_Page
  - Ensure all tests pass, ask the user if questions arise.

- [x] 12. Implement Infrastructure as Code (IaC)
  - [x] 12.1 Define VPC with public and private subnets, NAT Gateway, and VPC PrivateLink endpoints
    - Private subnets for Fargate tasks (no public IP assignment)
    - NAT Gateway in public subnet for outbound traffic to Google OAuth endpoints only
    - VPC Interface Endpoints (PrivateLink): ECR API, ECR DKR, STS, Secrets Manager, KMS, CloudWatch Logs, CloudWatch Monitoring
    - VPC Gateway Endpoint: S3
    - All AWS service traffic stays on private network — no internet traversal
    - _Requirements: 6.1, 6.2_

  - [x] 12.2 Define ECS Fargate cluster and service definitions
    - Three Fargate services: `clearfin-auth-service`, `clearfin-sts-broker`, `clearfin-secrets-hierarchy-manager`
    - Task definitions referencing ECR repositories
    - Non-root user execution, no secrets baked into images
    - _Requirements: 6.1_

  - [x] 12.3 Define ECR repositories with security configuration
    - Three repositories: `clearfin/auth-service`, `clearfin/sts-broker`, `clearfin/secrets-hierarchy-manager`
    - Image tag immutability, scan on push, lifecycle policy (retain last 10 tagged, expire untagged after 7 days)
    - AES-256 encryption via KMS, repository policy restricting push/pull access
    - _Requirements: 6.1_

  - [x] 12.4 Define ALB with TLS 1.2+ termination and health check configuration
    - TLS 1.2 minimum protocol version for all inbound connections
    - Health check targeting Auth_Service `/health` endpoint
    - _Requirements: 6.3, 6.6_

  - [x] 12.5 Define CloudFront distribution and S3 bucket for Login_Page
    - S3 bucket with public access blocked, OAC for CloudFront access
    - CloudFront distribution with HTTPS-only
    - Response headers policy for `Content-Security-Policy`
    - _Requirements: 8.6_

  - [x] 12.6 Define KMS keys, IAM roles, and trust policies
    - Per-environment KMS customer-managed key (AES-256) for secrets and session data encryption
    - Fargate task execution roles with ECR pull access
    - STS base role for JIT credential assumption
    - Platform service roles for Auth_Service, STS_Broker, Secrets_Hierarchy_Manager
    - _Requirements: 2.2, 4.3, 4.8_

  - [x] 12.7 Define CloudTrail configuration for audit logging
    - Log all Secrets Manager access events with caller Tenant_ID and session name
    - Monitor IAM, STS, and Secrets Manager policy modifications
    - _Requirements: 6.4, 6.5_

  - [x] 12.8 Define Sentinel_Gate CI/CD pipeline integration
    - Pipeline stage that blocks promotion until sentinel approval
    - Artifact validation step before approval request
    - _Requirements: 5.1, 5.2, 5.3_

- [x] 13. Implement Dockerfiles for each service
  - [x] 13.1 Create multi-stage Dockerfiles for Auth_Service, STS_Broker, and Secrets_Hierarchy_Manager
    - Build stage → production stage with Node.js Alpine base
    - Non-root user execution
    - No secrets in images — all fetched at runtime via JIT credentials
    - _Requirements: 6.1_

- [x] 14. Wire components together and integration testing
  - [x] 14.1 Wire Auth_Service callback to Session Manager and user upsert
    - Complete flow: callback validation → token exchange → id_token validation → user upsert → session creation → cookie set → redirect to dashboard
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 2.1_

  - [x] 14.2 Wire STS_Broker to Secrets Manager access via JIT credentials
    - Complete flow: service identity verification → tenant validation → session policy build → STS AssumeRole → return JIT credential
    - _Requirements: 3.1, 3.2, 3.3, 3.5, 3.6, 3.7_

  - [x] 14.3 Wire Sentinel_Gate into deployment pipeline
    - Complete flow: artifact validation → submit for approval → record decision → promote or halt
    - Kill-switch integration for bypass detection
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5_

  - [x] 14.4 Write integration tests
    - Mock Google OAuth endpoints: full login → callback → session creation flow
    - STS AssumeRole with scoped session policy
    - Secrets Manager provisioning at correct paths with encryption and rotation
    - Session logout token invalidation within 1-second SLA
    - _Requirements: 1.1–1.8, 2.1–2.7, 3.1–3.7, 4.1–4.10_

- [x] 15. Final checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties using `fast-check`
- Unit tests validate specific examples and edge cases
- Implementation language: TypeScript (as specified in the design document)
