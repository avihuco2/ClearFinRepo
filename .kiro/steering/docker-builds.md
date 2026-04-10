---
inclusion: auto
fileMatchPattern: "**/Dockerfile"
---

# ClearFin Docker Build Guide

## Service Ports

| Service | Port | ECR Repository |
|---|---|---|
| auth-service | 3000 | clearfin/auth-service |
| sts-broker | 3001 | clearfin/sts-broker |
| secrets-hierarchy-manager | 3002 | clearfin/secrets-hierarchy-manager |

## Build Commands

Build from the repo root (Dockerfiles reference workspace structure):

```bash
docker build -f packages/auth-service/Dockerfile -t clearfin/auth-service .
docker build -f packages/sts-broker/Dockerfile -t clearfin/sts-broker .
docker build -f packages/secrets-hierarchy-manager/Dockerfile -t clearfin/secrets-hierarchy-manager .
```

## Dockerfile Pattern

All services follow the same multi-stage pattern:
1. Build stage: `node:22-alpine`, install all deps, compile TypeScript (shared + service)
2. Production stage: `node:22-alpine`, production deps only, copy compiled `dist/`
3. Non-root user: `appuser` UID 1000
4. HEALTHCHECK: `wget -qO- http://localhost:{port}/health`
5. No secrets in image — use runtime environment variables

## Dependencies

Each service depends on `@clearfin/shared`, so the build stage must compile shared first:
```dockerfile
RUN npm run build --workspace=packages/shared
RUN npm run build --workspace=packages/{service}
```
