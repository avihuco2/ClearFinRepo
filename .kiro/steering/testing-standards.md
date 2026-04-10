---
inclusion: auto
fileMatchPattern: "packages/**/*.test.ts"
---

# ClearFin Testing Standards

## Framework

- vitest for all tests, fast-check for property-based tests
- Config: `vitest.config.ts` at root, includes `packages/**/*.test.ts`
- Run all: `npm test` or `npx vitest run`
- Run one package: `npx vitest run packages/auth-service/`

## Test Types

### Unit Tests (`*.test.ts`)
- Test specific examples, edge cases, and error conditions
- Use concrete values (known timestamps, specific IDs, boundary values)
- Example: "10th request succeeds, 11th returns 429"

### Property Tests (`*.property.test.ts`)
- Validate universal correctness properties using fast-check
- Minimum 100 iterations per property (`{ numRuns: 100 }`)
- Use `fc.assert(fc.property(...))` or `fc.assert(fc.asyncProperty(...))`
- Each property test references a design property (e.g. "Property 19: Callback Rate Limiting")

### Integration Tests (`*.integration.test.ts`)
- Test complete flows end-to-end with mocked external dependencies
- Example: login redirect → callback → token exchange → session creation

## Patterns

- Silent logger for tests: `createLogger("test", "test-corr-id", {}, () => {})`
- Injectable clocks: pass `() => fixedTime` to constructors for deterministic time
- Fresh instances per test: create new validator/manager in `beforeEach` or per property run
- Use `fc.pre(condition)` to skip invalid generated inputs in property tests

## Result Type Assertions

```typescript
const result = someFunction();
expect(result.ok).toBe(true);
if (!result.ok) return; // type narrowing
expect(result.value.field).toBe(expected);
```

## Security Test Requirements

- Rate limiting: test at boundary (10th and 11th request)
- Brute-force: test at boundary (4th and 5th failure)
- Token replay: test with consumed tokens triggering family revocation
- Cross-tenant: test with mismatched tenant IDs
- Logout SLA: verify completion within 1 second
