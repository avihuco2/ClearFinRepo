# GitHub Environment Configuration

This document describes the GitHub Actions environment setup required for the ClearFin Secure Foundation CI/CD pipeline. The pipeline uses three environments (`dev`, `staging`, `prod`) with OIDC-based AWS authentication — no long-lived AWS credentials are stored in GitHub.

## Prerequisites

Before configuring environments, ensure the following are in place:

1. An AWS IAM OIDC identity provider for `token.actions.githubusercontent.com` exists in each target AWS account.
2. Per-environment IAM roles with OIDC trust policies have been created (see [IAM Roles](#iam-roles) below).
3. CDK has been bootstrapped in each account/region using the `ClearFin CDK Bootstrap` workflow (`.github/workflows/bootstrap.yml`).

## Environments

### `dev`

- **Branch trigger:** `develop`
- **Protection rules:** None (auto-deploy on push)
- **Sentinel Gate:** Not required

### `staging`

- **Branch trigger:** `main`
- **Protection rules:**
  - Required reviewer: `clearfin_sentinel`
  - Review timeout: 60 minutes (workflow cancelled on timeout)
- **Sentinel Gate:** Required — deployment pauses until `clearfin_sentinel` approves

### `prod`

- **Branch trigger:** `main` (runs after successful staging deployment)
- **Protection rules:**
  - Required reviewer: `clearfin_sentinel`
  - Review timeout: 60 minutes (workflow cancelled on timeout)
- **Sentinel Gate:** Required — separate approval from staging

## Required Environment Variables

Each environment must have the following variables configured in **Settings → Environments → [env] → Environment variables** (not secrets — these are non-sensitive configuration values consumed via `${{ vars.* }}`):

| Variable | Description | Example |
|---|---|---|
| `AWS_ACCOUNT_ID` | AWS account ID for the target environment | `123456789012` |
| `AWS_REGION` | AWS region for deployment | `il-central-1` |
| `AWS_ROLE_ARN` | ARN of the OIDC-assumed IAM role | `arn:aws:iam::123456789012:role/clearfin-dev-github-actions-deploy` |
| `DOMAIN_NAME` | Domain name for the environment | `dev.clearfin.example.com` |
| `CERTIFICATE_ARN` | ACM certificate ARN for TLS termination | `arn:aws:acm:il-central-1:123456789012:certificate/abc-123` |

All five variables must be set for every environment. The pipeline will fail if any are missing.

## IAM Roles

Each environment uses a dedicated IAM role assumed via OIDC. The trust policy restricts which branches can assume the role:

| Environment | IAM Role Name | Allowed Branches |
|---|---|---|
| `dev` | `clearfin-dev-github-actions-deploy` | `main`, `develop` |
| `staging` | `clearfin-staging-github-actions-deploy` | `main` |
| `prod` | `clearfin-prod-github-actions-deploy` | `main` |

Each role's trust policy uses a `StringLike` condition on `token.actions.githubusercontent.com:sub` scoped to the repository and branch pattern. See `packages/infra/src/cdk/oidc-provider.ts` for the CDK construct that provisions these roles.

### Role Permissions (least-privilege)

- **ECR:** `GetAuthorizationToken`, `BatchCheckLayerAvailability`, `PutImage`, `InitiateLayerUpload`, `UploadLayerPart`, `CompleteLayerUpload`, `DescribeImageScanFindings`
- **CDK deploy:** `cloudformation:*` scoped to `clearfin-*` stacks, `sts:AssumeRole` for CDK execution roles, `ssm:GetParameter` for CDK bootstrap version
- **S3:** `PutObject`, `DeleteObject`, `ListBucket` scoped to `clearfin-{env}-login-page`
- **CloudFront:** `CreateInvalidation` scoped to the environment's distribution

## Setup Steps

### 1. Create GitHub Environments

In the repository, go to **Settings → Environments** and create three environments: `dev`, `staging`, `prod`.

### 2. Configure Protection Rules

For `staging` and `prod`:
1. Enable **Required reviewers**
2. Add `clearfin_sentinel` as a required reviewer
3. Set **Wait timer** to 0 (the 60-minute timeout is enforced by the reviewer response window)

Leave `dev` with no protection rules.

### 3. Set Environment Variables

For each environment, add the five variables listed above with the correct values for that environment's AWS account.

### 4. Bootstrap CDK

Run the `ClearFin CDK Bootstrap` workflow manually for each environment:
1. Go to **Actions → ClearFin CDK Bootstrap**
2. Click **Run workflow**
3. Select the target environment (`dev`, `staging`, or `prod`)

This provisions the CDKToolkit stack (S3 staging bucket, ECR repository, IAM roles) in the target account with the `clearfin` qualifier.

## Pipeline Flow Summary

```
Push to develop → build → test → docker → cdk synth → deploy dev (auto)
Push to main    → build → test → docker → cdk synth → deploy staging (sentinel) → deploy prod (sentinel)
PR to main      → build → test (no deploy)
```
