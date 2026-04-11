# Implementation Plan: Google SSO Integration

## Overview

Wire the existing auth-service and login page to production at `clearfin.click`. Infrastructure changes (IAM, ECS env vars, CloudFront ALB origin) come first, followed by the login page visual redesign, CSP update, and tests. The auth-service application code already exists — this is configuration, wiring, and UI work.

## Tasks

- [x] 1. Add Secrets Manager IAM policy for auth-service task role
  - [x] 1.1 Add `secretsmanager:GetSecretValue` inline policy to auth-service task role in `buildIamConfig()` (`packages/infra/src/iam.ts`)
    - Add a new inline policy `secrets-read-google-oauth` to the `auth-service` task role
    - Resource: `arn:aws:secretsmanager:${region}:${accountId}:secret:/clearfin/${env}/_platform/google-oauth-*`
    - The wildcard suffix accounts for the random 6-character suffix Secrets Manager appends
    - _Requirements: 2.3_

  - [x] 1.2 Write unit test for IAM policy in `buildIamConfig()` output
    - Verify the `clearfin-${env}-auth-service-task` role includes `secretsmanager:GetSecretValue` action
    - Verify the resource ARN is scoped to `/clearfin/${env}/_platform/google-oauth-*`
    - Add test in `packages/infra/src/infra.test.ts` or appropriate test file
    - _Requirements: 2.3_

- [x] 2. Configure auth-service environment variables
  - [x] 2.1 Add production environment variables to auth-service in `buildEcsClusterConfig()` (`packages/infra/src/ecs.ts`)
    - Add `GOOGLE_OAUTH_SECRET_NAME`, `REDIRECT_URI`, `REDIRECT_URI_ALLOWLIST`, `DASHBOARD_URL`, `EXPECTED_ISS`, `PORT` to auth-service environment
    - Only add these env vars for the auth-service, not other services
    - _Requirements: 4.1, 4.2, 4.3, 4.4_

  - [x] 2.2 Write unit test for auth-service environment variables
    - Verify `buildEcsClusterConfig()` output for auth-service contains correct `REDIRECT_URI`, `DASHBOARD_URL`, `EXPECTED_ISS`, `GOOGLE_OAUTH_SECRET_NAME`
    - _Requirements: 4.1, 4.2, 4.3, 4.4_

- [x] 3. Checkpoint — Verify config builder changes
  - Ensure all tests pass, ask the user if questions arise.

- [x] 4. Add CloudFront ALB origin and `/auth/*` cache behavior
  - [x] 4.1 Extend `StaticHostingCdkStackProps` with optional `albDnsName` prop (`packages/infra/src/cdk/static-hosting-stack.ts`)
    - Add `albDnsName?: string` to `StaticHostingCdkStackProps`
    - When `albDnsName` is provided, create an `HttpOrigin` with `https-only` protocol policy
    - Add `/auth/*` cache behavior with `CachingDisabled`, `AllViewerExceptHostHeader`, `ALLOW_ALL` methods, `REDIRECT_TO_HTTPS`
    - _Requirements: 3.1, 3.2, 3.3, 3.5_

  - [x] 4.2 Write CDK assertion tests for CloudFront ALB origin
    - Create a second test stack with `albDnsName` provided
    - Assert CloudFront distribution has a second origin with HTTPS-only protocol
    - Assert `/auth/*` cache behavior exists with CachingDisabled policy
    - Assert `/auth/*` behavior uses AllViewerExceptHostHeader origin request policy
    - Assert `/auth/*` behavior allows all HTTP methods
    - Add tests in `packages/infra/src/cdk/static-hosting-stack.test.ts`
    - _Requirements: 3.1, 3.2, 3.3, 3.5_

- [x] 5. Activate auth-service ECS Fargate service
  - [x] 5.1 Change `desiredCount` from `0` to `1` for auth-service in `compute-stack.ts` (`packages/infra/src/cdk/compute-stack.ts`)
    - Update the hardcoded `desiredCount: 0` to use the value from `svcCfg.desiredCount` (which comes from `buildEcsClusterConfig()` and is already `1` for non-prod / `2` for prod)
    - _Requirements: 5.1_

  - [x] 5.2 Write CDK assertion test for auth-service desiredCount
    - Assert auth-service Fargate service has `DesiredCount >= 1`
    - Assert auth-service Fargate service has `AssignPublicIp: DISABLED`
    - Add test in `packages/infra/src/cdk/compute-stack.test.ts`
    - _Requirements: 5.1, 5.3_

- [x] 6. Checkpoint — Verify infrastructure changes
  - Ensure all tests pass, ask the user if questions arise.

- [x] 7. Redesign login page with premium fintech aesthetic
  - [x] 7.1 Rewrite `renderLoginPage()` and `getStyles()` in `packages/login-page/src/login-page.ts`
    - Follow `.kiro/steering/frontend-design.md` guidelines
    - Typography: DM Serif Display (headings) + DM Sans (body) from Google Fonts
    - Color palette: dark refined theme with CSS custom properties (`--bg-primary: #0a0a0f`, `--accent-gold: #c9a84c`, etc.)
    - Layout: full-viewport atmospheric composition with gradient mesh background, not centered-card-on-flat-background
    - Animations: staggered `@keyframes` page-load reveals, button hover transitions, subtle gradient animation
    - Accessibility: WCAG 2.1 AA contrast ratios (gold on dark ≥ 4.5:1), `:focus-visible` indicators, `aria-label`, `role="alert"` for errors
    - Responsive: fluid layout 320px–1920px with CSS `clamp()` for typography
    - ClearFin branding: logo, name, tagline with strong visual hierarchy
    - Preserve existing functional elements: `id="google-signin-btn"`, `id="error-container"`, `id="error-message"`, `id="try-again-btn"`, inline script logic
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7, 8.8, 8.9_

  - [x] 7.2 Update login page unit tests for redesigned output (`packages/login-page/src/login-page.test.ts`)
    - Test HTML contains Google Fonts `<link>` for DM Serif Display and DM Sans
    - Test CSS contains custom properties (`--bg-primary`, `--accent-gold`, etc.)
    - Test CSS contains `@keyframes` animation definitions
    - Test HTML contains ClearFin branding elements (logo, name, tagline)
    - Test HTML contains `aria-label` and `:focus-visible` styles
    - Test CSS contains `@media` responsive queries or `clamp()`
    - _Requirements: 8.2, 8.3, 8.4, 8.6, 8.7, 8.8_

- [x] 8. Update CSP to allow Google Fonts
  - [x] 8.1 Update `buildCspHeaderValue()` in `packages/login-page/src/login-page.ts`
    - Add `https://fonts.googleapis.com` to `style-src` directive
    - Add `https://fonts.gstatic.com` to a new `font-src` directive
    - _Requirements: 7.3_

  - [x] 8.2 Update `buildCloudFrontConfig()` CSP in `packages/infra/src/cloudfront.ts`
    - Add `https://fonts.googleapis.com` to `style-src` directive
    - Add `font-src https://fonts.gstatic.com` directive
    - Keep existing directives intact
    - _Requirements: 7.3_

  - [x] 8.3 Write property test: CSP connect-src includes configured origin (Property 2)
    - **Property 2: CSP connect-src includes the configured origin**
    - For any valid HTTPS origin string, `buildCspHeaderValue(origin)` SHALL produce a CSP header where `connect-src` contains that exact origin
    - Use `fast-check` with `fc.webUrl()` or custom HTTPS origin arbitrary
    - Add test in `packages/login-page/src/login-page.property.test.ts`
    - **Validates: Requirements 7.3**

- [x] 9. Checkpoint — Verify login page and CSP changes
  - Ensure all tests pass, ask the user if questions arise.

- [x] 10. Write property test for error message safety
  - [x] 10.1 Write property test: error messages never leak internal details (Property 1)
    - **Property 1: Error messages never leak internal details**
    - For any error query parameter value (arbitrary strings, special characters, injection attempts), `handlePostAuth` SHALL return `kind: "error"` with the fixed generic message — never exposing the raw error value
    - Use `fast-check` with `fc.string()` and `fc.unicodeString()` arbitraries
    - Add test in `packages/login-page/src/login-page.property.test.ts`
    - **Validates: Requirements 6.5**

- [x] 11. Final checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Secrets Manager provisioning is a manual step (documented in design, not coded)
- The auth-service application code already exists — no changes needed to `packages/auth-service/src/`
- The `desiredCount: 0` in `compute-stack.ts` is hardcoded and overrides the config value — task 5.1 fixes this
- Property tests use `fast-check` which is already a project dependency
- Each task references specific requirements for traceability
