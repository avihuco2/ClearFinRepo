# Implementation Plan: GitHub Actions Deployment Pipeline

## Overview

Implement the CI/CD pipeline for ClearFin Secure Foundation using GitHub Actions and AWS CDK, targeting the `il-central-1` (Tel Aviv) region. The implementation starts with pure pipeline helper functions (testable), then CDK stack definitions consuming existing config builders (including VPC PrivateLink endpoints for all AWS service traffic), then the GitHub Actions workflow YAML files, and finally wiring everything together with OIDC trust policy constructs and documentation.

## Tasks

- [x] 1. Implement pipeline helper functions
  - [x] 1.1 Create `packages/infra/src/pipeline-helpers.ts` with OIDC trust policy generation, artifact summary extraction, cache-control header selection, deployment summary formatting, image tag construction, and action SHA pinning validation
    - `buildOidcTrustPolicy(env, accountId, org, repo)` → returns trust policy JSON with branch-scoped conditions
    - `extractArtifactSummary(cfnTemplates)` → categorizes IAM/STS/SM policies from CDK synth output
    - `getCacheControlHeader(filename)` → returns correct Cache-Control for index.html vs hashed assets
    - `formatDeploymentSummary(input)` → produces summary string with all required fields
    - `buildImageTag(gitSha)` → returns short SHA (first 7 chars)
    - `isValidActionShaPin(usesRef)` → validates third-party action uses 40-char hex SHA
    - Export all functions from `packages/infra/src/index.ts`
    - _Requirements: 1.3, 5.3, 6.3, 9.1, 9.4_

  - [x] 1.2 Write unit tests for pipeline helper functions in `packages/infra/src/pipeline-helpers.test.ts`
    - Test OIDC trust policy: dev allows `main` + `develop`, staging allows `main` only, prod allows `main` only
    - Test artifact summary: extracts IAM, STS, SM policies; reports missing components
    - Test cache-control: `index.html` → `no-cache`, `app.abc123.js` → `max-age=31536000, immutable`
    - Test deployment summary: all fields present in output
    - Test image tag: 7-char short SHA from full 40-char hash
    - Test action SHA pinning: accepts 40-char hex, rejects `v4`, `latest`, `main`
    - _Requirements: 1.3, 5.3, 6.3, 9.1, 9.4_

  - [x] 1.3 Write property test for OIDC trust policy branch restrictions (`packages/infra/src/pipeline-helpers.property.test.ts`)
    - **Property 1: OIDC Trust Policy Branch Restrictions**
    - Generate random environment names from {dev, staging, prod}, verify branch conditions match exactly
    - **Validates: Requirements 1.3**

  - [x] 1.4 Write property test for artifact bundle summary extraction
    - **Property 2: Artifact Bundle Summary Extraction**
    - Generate random CloudFormation template objects with random subsets of IAM/STS/SM policies, verify extraction completeness
    - **Validates: Requirements 5.3**

  - [x] 1.5 Write property test for cache-control header selection
    - **Property 3: Cache-Control Header Selection**
    - Generate random filenames (with/without hashes, various extensions), verify correct header; no filename gets undefined
    - **Validates: Requirements 6.3**

  - [x] 1.6 Write property test for deployment summary completeness
    - **Property 4: Deployment Summary Completeness**
    - Generate random git SHAs, image tag maps, stack name lists, sentinel statuses, durations; verify all fields present
    - **Validates: Requirements 9.4**

  - [x] 1.7 Write property test for third-party action SHA pinning
    - **Property 5: Third-Party Action SHA Pinning**
    - Generate random action reference strings, verify SHA format validation (40-char hex only)
    - **Validates: Requirements 9.1**

  - [x] 1.8 Write property test for image tag consistency
    - **Property 6: Image Tag Consistency Across Environments**
    - Generate random git SHAs and environment lists, verify all derived tags match the same source SHA
    - **Validates: Requirements 7.5**

- [x] 2. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 3. Implement CDK stack definitions
  - [x] 3.1 Create `packages/infra/src/cdk/stacks.ts` with four CDK stack classes: `ClearFinNetworkingStack`, `ClearFinComputeStack`, `ClearFinSecurityStack`, `ClearFinStaticHostingStack`
    - Each stack consumes the existing `build*Config()` functions from `packages/infra/src/`
    - `ClearFinNetworkingStack` creates VPC, subnets, NAT Gateways, and all VPC PrivateLink endpoints (ECR API, ECR DKR, STS, Secrets Manager, KMS, CloudWatch Logs, CloudWatch Monitoring, S3 Gateway) from `buildVpcConfig()`
    - `ClearFinComputeStack` depends on NetworkingStack and SecurityStack
    - All stacks accept `CdkStackContext` (environment, accountId, region, imageTag, domainName, certificateArn)
    - All stacks apply `Project`, `Environment`, `Component` tags per existing conventions
    - Target region: `il-central-1`
    - Export stack classes from `packages/infra/src/index.ts`
    - _Requirements: 4.2, 8.2, 8.3_

  - [x] 3.2 Create `packages/infra/src/cdk/app.ts` CDK app entry point
    - Instantiate all four stacks with environment context from CDK context parameters
    - Wire stack dependencies (ComputeStack depends on NetworkingStack, SecurityStack)
    - Pass `imageTag` from CDK context for Docker image references in ECS task definitions
    - _Requirements: 4.4, 7.5_

  - [x] 3.3 Create OIDC trust policy CDK construct in `packages/infra/src/cdk/oidc-provider.ts`
    - CDK construct that creates the IAM OIDC provider for `token.actions.githubusercontent.com`
    - Creates per-environment IAM roles with branch-scoped trust policies using `buildOidcTrustPolicy()`
    - Attaches scoped permissions for ECR push, CDK deploy, S3 sync, CloudFront invalidation
    - _Requirements: 1.1, 1.2, 1.3, 1.4_

  - [x] 3.4 Write CDK snapshot tests in `packages/infra/src/cdk/stacks.test.ts`
    - Snapshot test for each of the four stacks verifying synthesized CloudFormation output
    - Verify all resources include `Project`, `Environment`, `Component` tags
    - _Requirements: 8.2, 8.3_

- [x] 4. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 5. Create GitHub Actions workflow files
  - [x] 5.1 Create `.github/workflows/deploy.yml` with all seven jobs
    - `build-and-test`: checkout, Node 22, cache node_modules (keyed on package-lock.json hash), `npm ci`, `npm run build`, `npm test`
    - `docker-build-push`: OIDC auth, ECR login, matrix build for 3 services with BuildKit cache (`type=gha`), tag with short git SHA, verify ECR scan
    - `cdk-synth`: `npm ci`, build, `cdk synth`, upload `cdk.out` artifact
    - `deploy-dev`: condition `refs/heads/develop`, environment `dev`, OIDC auth, download cdk.out, `cdk diff`, `cdk deploy --require-approval never`, build login page, S3 sync with cache headers, CloudFront invalidation
    - `deploy-staging`: condition `refs/heads/main`, environment `staging` (protection rules → Sentinel Gate), same deploy steps targeting staging
    - `deploy-prod`: needs `deploy-staging`, condition `refs/heads/main`, environment `prod` (protection rules → Sentinel Gate), same deploy steps targeting prod
    - `summary`: `always()` condition, generate deployment summary (git SHA, image tags, stacks, sentinel status, duration)
    - All jobs have explicit `permissions` blocks with minimum required scopes
    - All third-party actions pinned to commit SHAs
    - Triggers: push to `main`/`develop`, PR to `main`
    - _Requirements: 1.1, 1.2, 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 4.1, 4.3, 4.4, 4.5, 4.6, 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 6.1, 6.2, 6.3, 6.4, 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 8.4, 9.1, 9.2, 9.3, 9.4_

  - [x] 5.2 Create `.github/workflows/bootstrap.yml` for CDK bootstrap
    - Trigger: `workflow_dispatch` with `environment` input (choice: dev, staging, prod)
    - Steps: OIDC auth with environment-specific role, `cdk bootstrap aws://{account}/{region}` with CDK qualifier
    - Explicit `permissions` block, third-party actions pinned to SHAs
    - _Requirements: 8.1, 9.1, 9.2_

- [x] 6. Create GitHub environment configuration documentation
  - [x] 6.1 Create `docs/github-environments.md` documenting required GitHub environment setup
    - Environment names: `dev`, `staging`, `prod`
    - Required environment variables per environment: `AWS_ACCOUNT_ID`, `AWS_REGION`, `AWS_ROLE_ARN`, `DOMAIN_NAME`, `CERTIFICATE_ARN`
    - Protection rules: staging and prod require `clearfin_sentinel` reviewer with 60-min timeout
    - Dev has no protection rules (auto-deploy)
    - _Requirements: 5.1, 5.2, 7.4_

- [x] 7. Write smoke tests for workflow validation
  - [x] 7.1 Write smoke tests in `packages/infra/src/workflow-smoke.test.ts`
    - Parse `deploy.yml` and `bootstrap.yml` as YAML and validate structure
    - Verify all third-party `uses:` references are pinned to 40-char hex SHAs (using `isValidActionShaPin`)
    - Verify each job has an explicit `permissions` block
    - Verify deploy jobs reference correct GitHub environments (`dev`, `staging`, `prod`)
    - Verify `bootstrap.yml` has `workflow_dispatch` trigger with `environment` input
    - Verify no `AWS_ACCESS_KEY_ID` or `AWS_SECRET_ACCESS_KEY` strings appear in workflow files
    - _Requirements: 9.1, 9.2, 9.3_

- [x] 8. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document (Properties 1–6)
- CDK stacks consume existing `build*Config()` functions — no duplication of infrastructure logic
- All workflow YAML uses commit SHA pinning for third-party actions per security requirements
