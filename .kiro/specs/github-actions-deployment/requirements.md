# Requirements Document

## Introduction

This specification defines the CI/CD deployment pipeline for ClearFin Secure Foundation (Phase 1) using GitHub Actions and AWS CDK, targeting the AWS `il-central-1` (Tel Aviv) region. The pipeline replaces the existing CodePipeline/CodeBuild references in `packages/infra/src/pipeline.ts` with GitHub Actions workflows that build, test, validate, and deploy the platform's seven packages across multiple environments (dev, staging, prod). The pipeline integrates the Sentinel Gate approval flow for security-sensitive deployments, uses OIDC federation for keyless AWS authentication, builds and pushes Docker images to ECR for the three backend services, deploys infrastructure via AWS CDK consuming the existing config objects in `packages/infra/` (including VPC PrivateLink endpoints for all AWS service traffic), and deploys the Login Page SPA to S3 with CloudFront invalidation.

## Glossary

- **GitHub_Actions_Pipeline**: The set of GitHub Actions workflows (YAML files in `.github/workflows/`) that orchestrate CI/CD for the ClearFin Secure Foundation monorepo.
- **OIDC_Provider**: The AWS IAM OIDC identity provider that trusts GitHub's OIDC token issuer (`token.actions.githubusercontent.com`), enabling GitHub Actions runners to assume AWS IAM roles without long-lived access keys.
- **CDK_Stack**: An AWS CDK construct that synthesizes and deploys CloudFormation stacks from the existing infrastructure config objects in `packages/infra/src/`.
- **Deployment_Environment**: One of three target environments (dev, staging, prod), each with its own AWS account or isolated resource set, IAM roles, and CDK stack parameters.
- **Artifact_Bundle**: The collection of built TypeScript packages, Docker images (tagged with git SHA), and CDK synthesized templates that constitute a single deployable unit.
- **Sentinel_Approval_Gate**: A GitHub Actions environment protection rule (for staging and prod) that requires manual approval from the `clearfin_sentinel` identity before the deployment job proceeds.
- **ECR_Image_Tag**: The immutable Docker image tag applied to each service image, formatted as the short git commit SHA (e.g., `abc1234`).
- **CloudFront_Invalidation**: The cache invalidation request issued after deploying new Login Page assets to S3, ensuring users receive the latest version.
- **CDK_Bootstrap**: The one-time AWS CDK bootstrap process that provisions the CDKToolkit stack (S3 staging bucket, ECR repository, IAM roles) in each target account/region.

## Requirements

### Requirement 1: OIDC-Based AWS Authentication

**User Story:** As a platform engineer, I want GitHub Actions to authenticate with AWS using OIDC federation, so that no long-lived AWS access keys are stored in GitHub secrets.

#### Acceptance Criteria

1. THE GitHub_Actions_Pipeline SHALL authenticate with AWS exclusively through OIDC federation using the `token.actions.githubusercontent.com` provider, with no long-lived AWS access key IDs or secret access keys stored in GitHub repository secrets or environment variables.
2. WHEN a workflow job requires AWS access, THE GitHub_Actions_Pipeline SHALL assume an IAM role specific to the target Deployment_Environment using the GitHub OIDC token.
3. THE OIDC_Provider trust policy SHALL restrict role assumption to the specific GitHub repository and branch pattern: `main` branch for prod, `main` branch for staging, and `main` or `develop` branch for dev.
4. THE IAM role assumed via OIDC SHALL follow least-privilege principles, granting only the permissions required for the specific deployment stage (e.g., ECR push, CDK deploy, S3 sync).
5. IF the OIDC token exchange fails, THEN THE GitHub_Actions_Pipeline SHALL terminate the workflow run with a clear error message indicating the authentication failure and the target role ARN.

### Requirement 2: Monorepo Build and Test

**User Story:** As a developer, I want the pipeline to build and test all packages in the monorepo, so that every change is validated before deployment.

#### Acceptance Criteria

1. WHEN a push occurs to the `main` or `develop` branch, or a pull request targets the `main` branch, THE GitHub_Actions_Pipeline SHALL trigger the CI workflow.
2. THE GitHub_Actions_Pipeline SHALL install dependencies using `npm ci` with the workspace lockfile to ensure reproducible builds.
3. THE GitHub_Actions_Pipeline SHALL compile all TypeScript packages using `npm run build` (project references).
4. THE GitHub_Actions_Pipeline SHALL execute the full test suite using `npm test` (vitest --run) and report the results, including all 333 unit, property-based, and integration tests.
5. IF any test fails, THEN THE GitHub_Actions_Pipeline SHALL fail the workflow run and prevent progression to subsequent deployment stages.
6. THE GitHub_Actions_Pipeline SHALL cache the `node_modules` directory keyed on the `package-lock.json` hash to reduce build times on subsequent runs.

### Requirement 3: Docker Image Build and ECR Push

**User Story:** As a platform engineer, I want Docker images for the three backend services to be built and pushed to ECR with immutable tags, so that each deployment uses a traceable, scannable container image.

#### Acceptance Criteria

1. WHEN the build-and-test stage succeeds, THE GitHub_Actions_Pipeline SHALL build Docker images for `auth-service`, `sts-broker`, and `secrets-hierarchy-manager` using the multi-stage Dockerfiles in each package directory.
2. THE GitHub_Actions_Pipeline SHALL tag each Docker image with the short git commit SHA as the ECR_Image_Tag (e.g., `clearfin/auth-service:abc1234`).
3. THE GitHub_Actions_Pipeline SHALL authenticate to Amazon ECR using the OIDC-assumed IAM role and push all three images to their respective ECR repositories (`clearfin/auth-service`, `clearfin/sts-broker`, `clearfin/secrets-hierarchy-manager`).
4. THE GitHub_Actions_Pipeline SHALL use Docker layer caching (BuildKit cache) to reduce image build times on subsequent runs.
5. IF an ECR push fails for any image, THEN THE GitHub_Actions_Pipeline SHALL fail the workflow run and report which image and repository encountered the error.
6. THE GitHub_Actions_Pipeline SHALL verify that ECR image scanning completes for each pushed image and report any CRITICAL or HIGH severity vulnerabilities as workflow annotations.

### Requirement 4: AWS CDK Infrastructure Deployment

**User Story:** As a platform engineer, I want the pipeline to deploy infrastructure using AWS CDK consuming the existing config objects, so that infrastructure changes are version-controlled and repeatable.

#### Acceptance Criteria

1. WHEN Docker images are pushed and the Sentinel_Approval_Gate (for staging and prod) is satisfied, THE GitHub_Actions_Pipeline SHALL deploy infrastructure using `cdk deploy` with the synthesized stacks derived from the config objects in `packages/infra/src/`.
2. THE CDK_Stack SHALL consume the existing builder functions (`buildVpcConfig`, `buildEcsClusterConfig`, `buildEcrRepositoryConfigs`, `buildAlbConfig`, `buildCloudFrontConfig`, `buildIamConfig`, `buildCloudTrailConfig`) to construct the infrastructure for the target Deployment_Environment.
3. THE GitHub_Actions_Pipeline SHALL run `cdk diff` before `cdk deploy` and include the diff output in the workflow logs for auditability.
4. THE GitHub_Actions_Pipeline SHALL pass the Deployment_Environment name, AWS account ID, and region as CDK context parameters.
5. IF `cdk deploy` fails, THEN THE GitHub_Actions_Pipeline SHALL fail the workflow run, log the CloudFormation error events, and leave the stack in a rollback-capable state.
6. THE GitHub_Actions_Pipeline SHALL deploy CDK stacks with the `--require-approval never` flag only after the Sentinel_Approval_Gate has been satisfied for the target environment.

### Requirement 5: Sentinel Gate Integration

**User Story:** As the clearfin_sentinel security auditor, I want the GitHub Actions pipeline to require my explicit approval before deploying to staging and production, so that no unauthorized infrastructure changes reach those environments.

#### Acceptance Criteria

1. WHEN a deployment targets the staging or prod Deployment_Environment, THE GitHub_Actions_Pipeline SHALL pause execution and require manual approval from the `clearfin_sentinel` identity before proceeding to the deploy stage.
2. THE Sentinel_Approval_Gate SHALL be implemented using GitHub Actions environment protection rules with required reviewers set to the `clearfin_sentinel` GitHub user or team.
3. THE GitHub_Actions_Pipeline SHALL generate an Artifact_Bundle summary (listing IAM policy documents, STS trust policies, and Secrets Manager resource policies included in the CDK synthesized output) and attach the summary to the approval request as a deployment review artifact.
4. WHEN clearfin_sentinel rejects a deployment, THE GitHub_Actions_Pipeline SHALL terminate the workflow run, log the rejection, and notify the deployment initiator via the GitHub Actions workflow summary.
5. IF the Sentinel_Approval_Gate times out after 60 minutes without a decision, THEN THE GitHub_Actions_Pipeline SHALL terminate the workflow run and log the timeout event.
6. THE GitHub_Actions_Pipeline SHALL record every approval and rejection decision in the workflow run logs with the timestamp, artifact commit SHA, and approver identity.
7. WHEN a deployment targets the dev Deployment_Environment, THE GitHub_Actions_Pipeline SHALL proceed without requiring Sentinel_Approval_Gate approval.

### Requirement 6: Login Page Deployment

**User Story:** As a platform engineer, I want the Login Page SPA to be deployed to S3 and served via CloudFront, so that users can access the authentication entry point with low latency and HTTPS enforcement.

#### Acceptance Criteria

1. WHEN the CDK infrastructure deployment succeeds, THE GitHub_Actions_Pipeline SHALL build the Login Page package and sync the built static assets to the S3 bucket designated for the target Deployment_Environment (`clearfin-{env}-login-page`).
2. THE GitHub_Actions_Pipeline SHALL issue a CloudFront_Invalidation for the path `/*` after uploading new assets to S3, ensuring users receive the latest Login Page version.
3. THE GitHub_Actions_Pipeline SHALL upload assets with appropriate `Cache-Control` headers: `max-age=31536000, immutable` for hashed assets and `no-cache` for `index.html`.
4. IF the S3 sync or CloudFront_Invalidation fails, THEN THE GitHub_Actions_Pipeline SHALL fail the workflow run and report the specific error.

### Requirement 7: Multi-Environment Pipeline Orchestration

**User Story:** As a platform engineer, I want the pipeline to support dev, staging, and prod environments with appropriate promotion gates, so that changes flow safely from development to production.

#### Acceptance Criteria

1. WHEN a push occurs to the `develop` branch, THE GitHub_Actions_Pipeline SHALL deploy to the dev Deployment_Environment automatically after build and test succeed.
2. WHEN a push occurs to the `main` branch, THE GitHub_Actions_Pipeline SHALL deploy to the staging Deployment_Environment after build, test, and Sentinel_Approval_Gate approval succeed.
3. WHEN the staging deployment succeeds, THE GitHub_Actions_Pipeline SHALL make the prod deployment available as a manually triggered subsequent job requiring a separate Sentinel_Approval_Gate approval.
4. THE GitHub_Actions_Pipeline SHALL pass environment-specific configuration (AWS account ID, region, domain name, certificate ARN) through GitHub Actions environment variables scoped to each Deployment_Environment.
5. THE GitHub_Actions_Pipeline SHALL ensure that each Deployment_Environment deployment uses the same Artifact_Bundle (same git SHA, same Docker image tags) to guarantee consistency across environments.
6. IF a deployment to any environment fails, THEN THE GitHub_Actions_Pipeline SHALL prevent automatic promotion to subsequent environments.

### Requirement 8: CDK Bootstrap and Stack Management

**User Story:** As a platform engineer, I want a documented and automated CDK bootstrap process, so that new environments can be provisioned reliably.

#### Acceptance Criteria

1. THE GitHub_Actions_Pipeline SHALL include a manually triggered workflow for running `cdk bootstrap` in a target Deployment_Environment with the OIDC-assumed IAM role.
2. THE CDK_Stack SHALL organize infrastructure into logical stacks: networking (VPC, subnets, NAT), compute (ECS, ECR, ALB), security (IAM, KMS, CloudTrail), and static hosting (S3, CloudFront).
3. THE CDK_Stack SHALL tag all deployed resources with `Project: ClearFin`, `Environment: {env}`, and `Component: {component}` tags matching the existing config object tag conventions.
4. THE GitHub_Actions_Pipeline SHALL run `cdk synth` as a validation step before deployment and fail the workflow if synthesis produces errors.
5. IF a CDK stack deployment fails mid-way, THEN THE GitHub_Actions_Pipeline SHALL log the CloudFormation stack events and leave the stack in a state that supports rollback or retry.

### Requirement 9: Pipeline Security and Auditability

**User Story:** As a security auditor, I want the pipeline itself to be secure and auditable, so that the CI/CD process does not introduce vulnerabilities.

#### Acceptance Criteria

1. THE GitHub_Actions_Pipeline SHALL pin all third-party GitHub Actions to specific commit SHAs (not mutable tags) to prevent supply-chain attacks.
2. THE GitHub_Actions_Pipeline SHALL use the minimum required GitHub token permissions (`permissions` block) for each job, following the principle of least privilege.
3. THE GitHub_Actions_Pipeline SHALL not expose AWS credentials, session tokens, or sensitive configuration values in workflow logs, using masking for all secret values.
4. THE GitHub_Actions_Pipeline SHALL produce a workflow run summary for each deployment that includes: git commit SHA, Docker image tags pushed, CDK stacks deployed, Sentinel approval status, and deployment duration.
5. WHEN a workflow run completes (success or failure), THE GitHub_Actions_Pipeline SHALL retain the workflow logs for a minimum of 90 days for audit purposes.
