// @clearfin/auth-service — User info extraction and upsert
// Extracts email, name, Google subject ID from validated id_token claims
// and creates or updates a UserRecord in the database.

import { randomUUID } from "node:crypto";
import { type Result, ok, err } from "@clearfin/shared";
import type { UserRecord } from "@clearfin/shared";
import type { UserClaims } from "./id-token-validator.js";

// ── Types ────────────────────────────────────────────────────────────

export interface UserRepositoryError {
  code: "UPSERT_FAILED";
  message: string;
}

export interface UserRepository {
  upsertUser(
    claims: UserClaims,
    tenantId: string,
  ): Promise<Result<UserRecord, UserRepositoryError>>;
}

// ── In-Memory Implementation ─────────────────────────────────────────

/**
 * In-memory UserRepository for development and testing.
 * Can be swapped for an Aurora-backed implementation later.
 */
export class InMemoryUserRepository implements UserRepository {
  /** Visible for testing — keyed by googleSubjectId */
  readonly users = new Map<string, UserRecord>();

  async upsertUser(
    claims: UserClaims,
    tenantId: string,
  ): Promise<Result<UserRecord, UserRepositoryError>> {
    const now = new Date();
    const existing = this.users.get(claims.sub);

    if (existing) {
      const updated: UserRecord = {
        ...existing,
        email: claims.email,
        name: claims.name,
        lastLoginAt: now,
        updatedAt: now,
      };
      this.users.set(claims.sub, updated);
      return ok(updated);
    }

    const record: UserRecord = {
      id: randomUUID(),
      googleSubjectId: claims.sub,
      email: claims.email,
      name: claims.name,
      tenantId,
      createdAt: now,
      updatedAt: now,
      lastLoginAt: now,
    };
    this.users.set(claims.sub, record);
    return ok(record);
  }
}
