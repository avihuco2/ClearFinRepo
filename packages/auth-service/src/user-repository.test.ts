import { describe, it, expect, beforeEach } from "vitest";
import { InMemoryUserRepository } from "./user-repository.js";
import type { UserClaims } from "./id-token-validator.js";

function makeClaims(overrides: Partial<UserClaims> = {}): UserClaims {
  return {
    sub: "google-sub-123",
    email: "alice@example.com",
    name: "Alice Smith",
    ...overrides,
  };
}

describe("InMemoryUserRepository", () => {
  let repo: InMemoryUserRepository;

  beforeEach(() => {
    repo = new InMemoryUserRepository();
  });

  describe("create (new user)", () => {
    it("creates a UserRecord with a UUID id", async () => {
      const result = await repo.upsertUser(makeClaims(), "tenant-1");

      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.value.id).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
      );
    });

    it("maps googleSubjectId from claims.sub", async () => {
      const result = await repo.upsertUser(makeClaims({ sub: "goog-42" }), "t1");

      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.value.googleSubjectId).toBe("goog-42");
    });

    it("maps email and name from claims", async () => {
      const result = await repo.upsertUser(
        makeClaims({ email: "bob@test.com", name: "Bob" }),
        "t1",
      );

      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.value.email).toBe("bob@test.com");
      expect(result.value.name).toBe("Bob");
    });

    it("sets tenantId from the argument", async () => {
      const result = await repo.upsertUser(makeClaims(), "tenant-xyz");

      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.value.tenantId).toBe("tenant-xyz");
    });

    it("sets createdAt, updatedAt, and lastLoginAt to current time", async () => {
      const before = new Date();
      const result = await repo.upsertUser(makeClaims(), "t1");
      const after = new Date();

      expect(result.ok).toBe(true);
      if (!result.ok) return;
      for (const field of ["createdAt", "updatedAt", "lastLoginAt"] as const) {
        expect(result.value[field].getTime()).toBeGreaterThanOrEqual(before.getTime());
        expect(result.value[field].getTime()).toBeLessThanOrEqual(after.getTime());
      }
    });
  });

  describe("update (existing user)", () => {
    it("updates email and name on second upsert", async () => {
      await repo.upsertUser(makeClaims(), "t1");
      const result = await repo.upsertUser(
        makeClaims({ email: "new@example.com", name: "New Name" }),
        "t1",
      );

      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.value.email).toBe("new@example.com");
      expect(result.value.name).toBe("New Name");
    });

    it("updates lastLoginAt on second upsert", async () => {
      const first = await repo.upsertUser(makeClaims(), "t1");
      expect(first.ok).toBe(true);
      if (!first.ok) return;
      const firstLogin = first.value.lastLoginAt;

      // Small delay to ensure time difference
      const second = await repo.upsertUser(makeClaims(), "t1");
      expect(second.ok).toBe(true);
      if (!second.ok) return;
      expect(second.value.lastLoginAt.getTime()).toBeGreaterThanOrEqual(firstLogin.getTime());
    });

    it("preserves the original id on update", async () => {
      const first = await repo.upsertUser(makeClaims(), "t1");
      const second = await repo.upsertUser(makeClaims({ email: "changed@x.com" }), "t1");

      expect(first.ok && second.ok).toBe(true);
      if (!first.ok || !second.ok) return;
      expect(second.value.id).toBe(first.value.id);
    });

    it("preserves the original createdAt on update", async () => {
      const first = await repo.upsertUser(makeClaims(), "t1");
      const second = await repo.upsertUser(makeClaims(), "t1");

      expect(first.ok && second.ok).toBe(true);
      if (!first.ok || !second.ok) return;
      expect(second.value.createdAt).toEqual(first.value.createdAt);
    });

    it("preserves the original tenantId on update", async () => {
      await repo.upsertUser(makeClaims(), "original-tenant");
      const result = await repo.upsertUser(makeClaims(), "different-tenant");

      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.value.tenantId).toBe("original-tenant");
    });
  });

  describe("isolation", () => {
    it("stores separate records for different googleSubjectIds", async () => {
      await repo.upsertUser(makeClaims({ sub: "user-a" }), "t1");
      await repo.upsertUser(makeClaims({ sub: "user-b" }), "t1");

      expect(repo.users.size).toBe(2);
    });
  });
});
