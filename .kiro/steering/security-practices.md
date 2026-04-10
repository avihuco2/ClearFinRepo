---
inclusion: always
---

# ClearFin Security Practices

## Zero Trust Principles

- No long-lived credentials anywhere — all access via JIT STS credentials (900s max)
- Every access is scoped to a specific tenant and action
- Cross-tenant isolation enforced at IAM policy level (`aws:PrincipalTag/tenant_id`)
- All secrets encrypted at rest with per-environment KMS keys (AES-256)

## Authentication

- Google SSO with PKCE (Authorization Code + code_challenge S256)
- State parameter: cryptographically random, one-time use, stored server-side
- id_token validation: signature (JWKS), aud (client ID), iss (`https://accounts.google.com`), exp
- Redirect URI: exact-match allowlist only, no wildcards

## Session Security

- JWT: 15-minute expiry, HMAC-SHA256, contains sub/tenantId/iat/exp/jti/tokenFamily
- Refresh tokens: 8-hour expiry, rotation on every use, token family tracking
- Replay detection: consumed token reuse → revoke entire token family (CRITICAL log)
- Logout: invalidate all tokens in family within 1 second

## Callback Hardening

- Rate limit: 10 requests per 60s per IP (HTTP 429)
- Brute-force: 5 consecutive failures in 5 min → 15-minute IP block (ALERT log)
- Input validation: code ≤ 2048 chars, URL-safe only, no unexpected query params
- Security headers: nosniff, DENY framing, no-store cache, HSTS

## Deployment Security

- Sentinel Gate: every deployment artifact must be approved by clearfin_sentinel
- Artifact validation: must contain IAM policies, STS trust policies, SM resource policies
- Kill-switch: bypass detection → revoke IAM permissions + CRITICAL alert
- CloudTrail: monitor IAM/STS/SM policy changes, alert within 60 seconds

## Container Security

- Multi-stage Docker builds, Node.js Alpine, non-root user (UID 1000)
- No secrets baked into images — all fetched at runtime
- ECR: immutable tags, scan-on-push, KMS encryption
- Fargate: private subnets only, no public IP assignment

## Network Security

- All AWS service traffic uses VPC PrivateLink endpoints (no internet traversal)
- Interface endpoints: ECR (api + dkr), STS, Secrets Manager, KMS, CloudWatch Logs, CloudWatch Monitoring
- Gateway endpoint: S3 (route-table based, no cost)
- NAT Gateway only for external traffic (Google OAuth endpoints)

## Never Do

- Never throw exceptions for expected failures — use Result<T, E>
- Never log PII (emails, names) — use subject IDs and tenant IDs
- Never expose internal error details to clients
- Never use wildcard IAM policies for tenant-scoped resources
- Never store secrets in environment variables baked into images
