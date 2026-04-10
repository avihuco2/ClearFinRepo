---
inclusion: auto
fileMatchPattern: "packages/**/*.ts"
---

# ClearFin Coding Conventions

## TypeScript

- Target: ES2022, module: Node16, strict mode
- All functions return `Result<T, E>` from `@clearfin/shared` for fallible operations — never throw
- Use `ok(value)` and `err(error)` constructors, never raw object literals
- Async functions return `Promise<Result<T, E>>`
- Error types are discriminated unions with a `code` string field (e.g. `"RATE_LIMIT_EXCEEDED"`)
- Imports use `.js` extension for Node16 module resolution: `import { ok } from "./types.js"`

## Dependency Injection

- All external services (AWS STS, Secrets Manager, Google OAuth, JWKS) use injected interfaces
- This enables testing without mocks of the implementation — just provide a test double
- Example: `STSClient`, `SecretsManagerClient`, `HttpClient`, `JwksFetcher`, `ServiceRegistry`, `TenantStore`

## Logging

- Use `createLogger(service, correlationId)` from `@clearfin/shared`
- Levels: INFO, WARN, ERROR, CRITICAL, ALERT
- CRITICAL = cross-tenant access violations, token replay, deployment bypass
- ALERT = brute-force detection, non-existent tenant requests, security-sensitive API changes
- Always include structured context (tenantId, sourceIp, etc.) — never log PII

## File Organization

- One module per concern (e.g. `callback-validator.ts`, `token-exchanger.ts`, `session-manager.ts`)
- Unit tests: `{module}.test.ts` alongside the source
- Property tests: `{module}.property.test.ts` alongside the source
- Integration tests: `{module}.integration.test.ts` alongside the source
- All public exports go through `index.ts` in each package

## Naming

- Interfaces: PascalCase (e.g. `UserRecord`, `STSSessionPolicy`)
- Error types: PascalCase with `Error` suffix (e.g. `RateLimitError`, `TokenError`)
- Functions: camelCase (e.g. `buildSessionPolicy`, `handleCallback`)
- Classes: PascalCase (e.g. `CallbackValidator`, `SessionManager`)
- Constants: UPPER_SNAKE_CASE (e.g. `RATE_LIMIT_MAX_REQUESTS`)
