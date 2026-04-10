// Property-based tests for Secrets_Hierarchy_Manager
// Uses fast-check for property testing, vitest as runner

import { describe, it, expect } from "vitest";
import fc from "fast-check";
import {
  buildTenantSecretPaths,
  buildPlatformSecretPaths,
  buildTenantResourcePolicy,
  buildPlatformResourcePolicy,
  checkCrossTenantAccess,
  SecretsHierarchyManager,
  type SecretsManagerClient,
  type SecretsHierarchyConfig,
} from "./secrets-hierarchy-manager.js";
import { createLogger } from "@clearfin/shared";
import type { SecretTags } from "@clearfin/shared";

// ── Helpers ──────────────────────────────────────────────────────────

const noop = () => {};
const silentLogger = createLogger("secrets-hierarchy-manager-test", "test-corr-id", {}, noop);

function makeMockClient(): SecretsManagerClient & { calls: { createSecret: unknown[]; putResourcePolicy: unknown[]; tagResource: unknown[] } } {
  const calls = { createSecret: [] as unknown[], putResourcePolicy: [] as unknown[], tagResource: [] as unknown[] };
  return {
    calls,
    createSecret: async (input) => {
      calls.createSecret.push(input);
      return { ARN: `arn:aws:secretsmanager:il-central-1:123456789012:secret:${input.Name}`, Name: input.Name };
    },
    putResourcePolicy: async (input) => { calls.putResourcePolicy.push(input); },
    rotateSecret: async () => {},
    tagResource: async (input) => { calls.tagResource.push(input); },
  };
}

function makeManager(env = "dev", platformRoleArns: string[] = []): { manager: SecretsHierarchyManager; client: ReturnType<typeof makeMockClient> } {
  const client = makeMockClient();
  const config: SecretsHierarchyConfig = {
    env,
    kmsKeyArn: "arn:aws:kms:il-central-1:123456789012:key/test-key",
    platformRoleArns,
  };
  return { manager: new SecretsHierarchyManager(config, client, silentLogger), client };
}

// Generators
const tenantIdArb = fc.stringMatching(/^[a-zA-Z0-9_-]{1,64}$/).filter((s) => s !== "_platform");
const envArb = fc.constantFrom("dev", "staging", "prod");
const arnArb = fc.stringMatching(/^arn:aws:iam::\d{12}:role\/[a-zA-Z0-9_-]{1,64}$/);

// ── Property 12: Secret Path Construction ────────────────────────────
// **Validates: Requirements 4.1, 4.7**

describe("Property 12: Secret Path Construction", () => {
  it("produces exactly three tenant paths with correct structure", () => {
    fc.assert(
      fc.property(tenantIdArb, envArb, (tenantId, env) => {
        const paths = buildTenantSecretPaths(env, tenantId);

        expect(paths).toHaveLength(3);
        expect(paths).toContain(`/clearfin/${env}/${tenantId}/bank-credentials`);
        expect(paths).toContain(`/clearfin/${env}/${tenantId}/api-keys`);
        expect(paths).toContain(`/clearfin/${env}/${tenantId}/config`);

        // Every path starts with /clearfin/{env}/{tenantId}/
        for (const path of paths) {
          expect(path).toMatch(new RegExp(`^/clearfin/${env}/${tenantId}/`));
        }
      }),
      { numRuns: 100 },
    );
  });

  it("produces exactly three platform paths with correct structure", () => {
    fc.assert(
      fc.property(envArb, (env) => {
        const paths = buildPlatformSecretPaths(env);

        expect(paths).toHaveLength(3);
        expect(paths).toContain(`/clearfin/${env}/_platform/database-credentials`);
        expect(paths).toContain(`/clearfin/${env}/_platform/ai-api-keys`);
        expect(paths).toContain(`/clearfin/${env}/_platform/service-config`);

        for (const path of paths) {
          expect(path).toMatch(new RegExp(`^/clearfin/${env}/_platform/`));
        }
      }),
      { numRuns: 100 },
    );
  });
});

// ── Property 13: Tenant Resource Policy Construction ─────────────────
// **Validates: Requirements 4.2**

describe("Property 13: Tenant Resource Policy Construction", () => {
  it("resource policy contains aws:PrincipalTag/tenant_id condition matching only the specified tenant_id", () => {
    fc.assert(
      fc.property(tenantIdArb, (tenantId) => {
        const secretArn = `arn:aws:secretsmanager:il-central-1:123456789012:secret:/clearfin/dev/${tenantId}/bank-credentials`;
        const policy = buildTenantResourcePolicy(tenantId, secretArn);

        expect(policy.Version).toBe("2012-10-17");
        expect(policy.Statement).toHaveLength(1);

        const stmt = policy.Statement[0];
        expect(stmt.Effect).toBe("Allow");
        expect(stmt.Resource).toBe(secretArn);
        expect(stmt.Condition).toBeDefined();
        expect(stmt.Condition!["StringEquals"]).toBeDefined();
        expect(stmt.Condition!["StringEquals"]["aws:PrincipalTag/tenant_id"]).toBe(tenantId);
      }),
      { numRuns: 100 },
    );
  });
});

// ── Property 14: Cross-Tenant Access Denial ──────────────────────────
// **Validates: Requirements 4.5**

describe("Property 14: Cross-Tenant Access Denial", () => {
  it("denies access when path tenant_id differs from caller tenant_id", () => {
    fc.assert(
      fc.property(
        tenantIdArb,
        tenantIdArb.filter((s) => s.length > 0),
        envArb,
        (pathTenantId, callerTenantId, env) => {
          const secretPath = `/clearfin/${env}/${pathTenantId}/bank-credentials`;
          const result = checkCrossTenantAccess(secretPath, callerTenantId);

          if (pathTenantId === callerTenantId) {
            expect(result.ok).toBe(true);
          } else {
            expect(result.ok).toBe(false);
            if (!result.ok) {
              expect(result.error.code).toBe("CROSS_TENANT_ACCESS_DENIED");
              expect(result.error.pathTenantId).toBe(pathTenantId);
              expect(result.error.callerTenantId).toBe(callerTenantId);
            }
          }
        },
      ),
      { numRuns: 100 },
    );
  });

  it("allows access to _platform paths regardless of caller tenant_id", () => {
    fc.assert(
      fc.property(tenantIdArb, envArb, (callerTenantId, env) => {
        const secretPath = `/clearfin/${env}/_platform/database-credentials`;
        const result = checkCrossTenantAccess(secretPath, callerTenantId);
        expect(result.ok).toBe(true);
      }),
      { numRuns: 100 },
    );
  });
});

// ── Property 15: Secret Metadata Tagging ─────────────────────────────
// **Validates: Requirements 4.6**

describe("Property 15: Secret Metadata Tagging", () => {
  const secretTypeArb = fc.constantFrom("bank-credentials", "api-keys", "config", "database-credentials", "ai-api-keys", "service-config");
  const createdByArb = fc.stringMatching(/^[a-zA-Z0-9_-]{1,64}$/);

  it("tags include tenant_id, environment, secret_type, created_by matching input", async () => {
    await fc.assert(
      fc.asyncProperty(
        tenantIdArb,
        envArb,
        secretTypeArb,
        createdByArb,
        async (tenantId, env, secretType, createdBy) => {
          const { manager, client } = makeManager(env);
          const secretArn = `arn:aws:secretsmanager:il-central-1:123456789012:secret:test`;
          const tags: SecretTags = {
            tenant_id: tenantId,
            environment: env,
            secret_type: secretType,
            created_by: createdBy,
          };

          const result = await manager.tagSecret(secretArn, tags);
          expect(result.ok).toBe(true);

          const call = client.calls.tagResource[client.calls.tagResource.length - 1] as { SecretId: string; Tags: Array<{ Key: string; Value: string }> };
          expect(call.SecretId).toBe(secretArn);

          const tagMap = Object.fromEntries(call.Tags.map((t: { Key: string; Value: string }) => [t.Key, t.Value]));
          expect(tagMap["tenant_id"]).toBe(tenantId);
          expect(tagMap["environment"]).toBe(env);
          expect(tagMap["secret_type"]).toBe(secretType);
          expect(tagMap["created_by"]).toBe(createdBy);
        },
      ),
      { numRuns: 100 },
    );
  });
});

// ── Property 16: Platform Resource Policy Construction ───────────────
// **Validates: Requirements 4.8**

describe("Property 16: Platform Resource Policy Construction", () => {
  it("allows only platform roles and denies principals with tenant_id tag", () => {
    fc.assert(
      fc.property(
        fc.uniqueArray(arnArb, { minLength: 1, maxLength: 5 }),
        (platformRoleArns) => {
          const secretArn = "arn:aws:secretsmanager:il-central-1:123456789012:secret:/clearfin/dev/_platform/database-credentials";
          const policy = buildPlatformResourcePolicy(platformRoleArns, secretArn);

          expect(policy.Version).toBe("2012-10-17");
          expect(policy.Statement).toHaveLength(2);

          // First statement: Allow platform roles
          const allowStmt = policy.Statement.find((s) => s.Sid === "AllowPlatformRoles")!;
          expect(allowStmt).toBeDefined();
          expect(allowStmt.Effect).toBe("Allow");
          expect(allowStmt.Principal).toEqual({ AWS: platformRoleArns });
          expect(allowStmt.Resource).toBe(secretArn);

          // Second statement: Deny tenant JIT credentials
          const denyStmt = policy.Statement.find((s) => s.Sid === "DenyTenantJITCredentials")!;
          expect(denyStmt).toBeDefined();
          expect(denyStmt.Effect).toBe("Deny");
          expect(denyStmt.Condition).toBeDefined();
          expect(denyStmt.Condition!["StringLike"]).toBeDefined();
          expect(denyStmt.Condition!["StringLike"]["aws:PrincipalTag/tenant_id"]).toEqual(["*"]);
        },
      ),
      { numRuns: 100 },
    );
  });
});
