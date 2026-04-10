// Property-based tests for user info extraction from id_token claims
// **Validates: Requirements 1.7**
// Property 4: User Info Extraction from id_token — For any valid id_token
// containing email, name, and subject claims, the Auth_Service extraction
// function SHALL return a user record where the email, name, and
// googleSubjectId fields exactly match the corresponding token claims.

import { describe, it, expect, beforeEach } from "vitest";
import * as fc from "fast-check";
import { InMemoryUserRepository } from "./user-repository.js";
import type { UserClaims } from "./id-token-validator.js";

// ── Generators ───────────────────────────────────────────────────────

/** Random email-like strings: {local}@{domain}.{tld} */
const emailArb = fc
  .tuple(
    fc.stringOf(fc.constantFrom(..."abcdefghijklmnopqrstuvwxyz0123456789._-".split("")), {
      minLength: 1,
      maxLength: 30,
    }),
    fc.stringOf(fc.constantFrom(..."abcdefghijklmnopqrstuvwxyz0123456789-".split("")), {
      minLength: 1,
      maxLength: 20,
    }),
    fc.stringOf(fc.constantFrom(..."abcdefghijklmnopqrstuvwxyz".split("")), {
      minLength: 2,
      maxLength: 6,
    }),
  )
  .map(([local, domain, tld]) => `${local}@${domain}.${tld}`);

/** Random human-like name strings. */
const nameArb = fc.stringOf(
  fc.constantFrom(..."abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ '-".split("")),
  { minLength: 1, maxLength: 60 },
);

/** Random Google subject ID (numeric string). */
const subjectIdArb = fc.stringOf(fc.constantFrom(..."0123456789".split("")), {
  minLength: 5,
  maxLength: 30,
});

/** Random tenant ID. */
const tenantIdArb = fc.stringOf(
  fc.constantFrom(..."abcdefghijklmnopqrstuvwxyz0123456789-".split("")),
  { minLength: 3, maxLength: 30 },
);

// ── Property Tests ───────────────────────────────────────────────────

describe("Property 4: User Info Extraction from id_token", () => {
  let repo: InMemoryUserRepository;

  beforeEach(() => {
    repo = new InMemoryUserRepository();
  });

  it("returned UserRecord email, name, and googleSubjectId exactly match input claims", () => {
    fc.assert(
      fc.asyncProperty(
        emailArb,
        nameArb,
        subjectIdArb,
        tenantIdArb,
        async (email, name, sub, tenantId) => {
          const claims: UserClaims = { sub, email, name };
          const result = await repo.upsertUser(claims, tenantId);

          expect(result.ok).toBe(true);
          if (!result.ok) return;

          expect(result.value.email).toBe(email);
          expect(result.value.name).toBe(name);
          expect(result.value.googleSubjectId).toBe(sub);
        },
      ),
      { numRuns: 100 },
    );
  });

  it("upsert preserves original id and createdAt on update with new claims", () => {
    fc.assert(
      fc.asyncProperty(
        emailArb,
        nameArb,
        emailArb,
        nameArb,
        subjectIdArb,
        tenantIdArb,
        async (email1, name1, email2, name2, sub, tenantId) => {
          const claims1: UserClaims = { sub, email: email1, name: name1 };
          const claims2: UserClaims = { sub, email: email2, name: name2 };

          const first = await repo.upsertUser(claims1, tenantId);
          expect(first.ok).toBe(true);
          if (!first.ok) return;

          const second = await repo.upsertUser(claims2, tenantId);
          expect(second.ok).toBe(true);
          if (!second.ok) return;

          // id and createdAt are preserved from the original record
          expect(second.value.id).toBe(first.value.id);
          expect(second.value.createdAt).toEqual(first.value.createdAt);

          // updated fields match the new claims
          expect(second.value.email).toBe(email2);
          expect(second.value.name).toBe(name2);
          expect(second.value.googleSubjectId).toBe(sub);
        },
      ),
      { numRuns: 100 },
    );
  });
});
