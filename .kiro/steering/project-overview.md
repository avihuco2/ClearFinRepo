---
inclusion: always
---

# ClearFin Secure Foundation — Project Overview

## What This Is

ClearFin is a multi-tenant fintech platform. This repo (`clearfin-secure-foundation`) is Phase 1: the security backbone. It implements Google SSO, AWS STS JIT credentials, hierarchical Secrets Manager, and a sentinel deployment gate.

## Monorepo Structure

```
packages/
  shared/              — Result<T,E>, domain types, structured logger
  auth-service/        — Google SSO, session management, callback validation
  sts-broker/          — JIT AWS STS credential issuance per tenant
  secrets-hierarchy-manager/ — Secrets Manager path hierarchy + policies
  sentinel-gate/       — Deployment approval checkpoint for CI/CD
  login-page/          — Static SPA (Sign in with Google)
  infra/               — IaC config objects (VPC, ECS, ECR, ALB, CloudFront, IAM, CloudTrail, Pipeline)
```

## Target Region

All AWS resources deploy to `il-central-1` (Tel Aviv). Availability zones: `il-central-1a`, `il-central-1b`.

## Key Commands

- `npm test` — run all tests (vitest, 333 tests across 28 files)
- `npm run build` — TypeScript build (project references)
- Test a single package: `npx vitest run --reporter=verbose packages/auth-service/`

## Spec Location

Requirements, design, and tasks live in `.kiro/specs/clearfin-secure-foundation/`.
