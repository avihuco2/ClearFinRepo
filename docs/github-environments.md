# GitHub Environment Configuration

This document describes the GitHub Actions environment setup required for the ClearFin Secure Foundation CI/CD pipeline. The pipeline deploys directly to `prod` on push to `main` — no dev or staging environments.

## Prerequisites

1. An AWS IAM OIDC identity provider for `token.actions.githubusercontent.com` exists in the prod AWS account.
2. A prod IAM role with OIDC trust policy has been created (see [IAM Roles](#iam-roles) below).
3. CDK has been bootstrapped in the prod account/region using the `ClearFin CDK Bootstrap` workflow (`.github/workflows/bootstrap.yml`).

## Environment

### `prod`

- **Branch trigger:** `main`
- **Protection rules:** None (automatic deploy on push, no manual approval)
- **Flow:** push to main → build → test → docker push → CDK synth → deploy prod

## Required Environment Variables

The `prod` environment must have the following variables configured in **Settings → Environments → prod → Environment variables**:

| Variable | Description | Example |
|---|---|---|
| `AWS_ACCOUNT_ID` | AWS account ID for prod | `123456789012` |
| `AWS_REGION` | AWS region for deployment | `il-central-1` |
| `AWS_ROLE_ARN` | ARN of the OIDC-assumed IAM role | `arn:aws:iam::123456789012:role/clearfin-prod-github-actions-deploy` |
| `DOMAIN_NAME` | Domain name for the environment | `clearfin.click` |
| `CERTIFICATE_ARN` | ACM certificate ARN for TLS termination | `arn:aws:acm:il-central-1:123456789012:certificate/abc-123` |

All five variables must be set. The pipeline will fail if any are missing.

## IAM Roles

| Environment | IAM Role Name | Allowed Branches |
|---|---|---|
| `prod` | `clearfin-prod-github-actions-deploy` | `main` |

The role's trust policy uses a `StringLike` condition on `token.actions.githubusercontent.com:sub` scoped to the repository and `main` branch. See `packages/infra/src/cdk/oidc-provider.ts` for the CDK construct that provisions this role.

### Role Permissions (least-privilege)

- **ECR:** `GetAuthorizationToken`, `BatchCheckLayerAvailability`, `PutImage`, `InitiateLayerUpload`, `UploadLayerPart`, `CompleteLayerUpload`, `DescribeImageScanFindings`
- **CDK deploy:** `cloudformation:*` scoped to `clearfin-*` stacks, `sts:AssumeRole` for CDK execution roles, `ssm:GetParameter` for CDK bootstrap version
- **S3:** `PutObject`, `DeleteObject`, `ListBucket` scoped to `clearfin-prod-login-page`
- **CloudFront:** `CreateInvalidation` scoped to the prod distribution

## Setup Steps

### 1. Create GitHub Environment

In the repository, go to **Settings → Environments** and ensure the `prod` environment exists. Remove any required reviewers or wait timers — deployments are fully automatic.

### 2. Remove dev and staging environments

Delete the `dev` and `staging` environments from **Settings → Environments** if they exist.

### 3. Set Environment Variables

Add the five variables listed above to the `prod` environment with the correct values.

### 4. Bootstrap CDK

Run the `ClearFin CDK Bootstrap` workflow manually for `prod`:
1. Go to **Actions → ClearFin CDK Bootstrap**
2. Click **Run workflow**
3. Select `prod`

## Pipeline Flow Summary

```
Push to main → build → test → docker push → cdk synth → deploy prod (automatic)
PR to main   → build → test (no deploy)
```
