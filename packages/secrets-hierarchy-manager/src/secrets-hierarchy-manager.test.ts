// Unit tests for Secrets_Hierarchy_Manager
// Validates: Requirements 4.1-4.10

import { describe, it, expect, vi } from "vitest";
import {
  SecretsHierarchyManager,
  buildTenantSecretPaths,
  buildPlatformSecretPaths,
  buildTenantResourcePolicy,
  buildPlatformResourcePolicy,
  checkCrossTenantAccess,
  type SecretsManagerClient,
  type SecretsHierarchyConfig,
  type CreateSecretInput,
} from "./secrets-hierarchy-manager.js";
import { createLogger } from "@clearfin/shared";
import type { SecretTags } from "@clearfin/shared";

// ── Helpers ──────────────────────────────────────────────────────────

const noop = () => {};
const silentLogger = createLogger("secrets-hierarchy-manager-test", "test-corr-id", {}, noop);

function makeMockClient(overrides: Partial<SecretsManagerClient> = {}): SecretsManagerClient & { createSecretCalls: CreateSecretInput[] } {
  const createSecretCalls: CreateSecretInput[] = [];
  return {
    createSecretCalls,
    createSecret: overrides.createSecret ?? (async (input) => {
      createSecretCalls.push(input);
      return { ARN: `arn:aws:secretsmanager:il-central-1:123456789012:secret:${input.Name}`, Name: input.Name };
    }),
    putResourcePolicy: overrides.putResourcePolicy ?? (async () => {}),
    rotateSecret: overrides.rotateSecret ?? (async () => {}),
    tagResource: overrides.tagResource ?? (async () => {}),
  };
}

function makeManager(
  env = "dev",
  platformRoleArns: string[] = ["arn:aws:iam::123456789012:role/auth-service", "arn:aws:iam::123456789012:role/sts-broker"],
  clientOverrides: Partial<SecretsManagerClient> = {},
) {
  const client = makeMockClient(clientOverrides);
  const config: SecretsHierarchyConfig = {
    env,
    kmsKeyArn: "arn:aws:kms:il-central-1:123456789012:key/test-key",
    platformRoleArns,
  };
  return { manager: new SecretsHierarchyManager(config, client, silentLogger), client };
}

// ── Path construction (Req 4.1) ──────────────────────────────────────

describe("Tenant secret path construction", () => {
  it("creates three paths for tenant-abc in dev", () => {
    const paths = buildTenantSecretPaths("dev", "tenant-abc");
    expect(paths).toEqual([
      "/clearfin/dev/tenant-abc/bank-credentials",
      "/clearfin/dev/tenant-abc/api-keys",
      "/clearfin/dev/tenant-abc/config",
    ]);
  });

  it("creates three paths for tenant-xyz in prod", () => {
    const paths = buildTenantSecretPaths("prod", "tenant-xyz");
    expect(paths).toEqual([
      "/clearfin/prod/tenant-xyz/bank-credentials",
      "/clearfin/prod/tenant-xyz/api-keys",
      "/clearfin/prod/tenant-xyz/config",
    ]);
  });
});

// ── Platform path construction (Req 4.7) ─────────────────────────────

describe("Platform secret path construction", () => {
  it("creates three platform paths in dev", () => {
    const paths = buildPlatformSecretPaths("dev");
    expect(paths).toEqual([
      "/clearfin/dev/_platform/database-credentials",
      "/clearfin/dev/_platform/ai-api-keys",
      "/clearfin/dev/_platform/service-config",
    ]);
  });

  it("creates three platform paths in staging", () => {
    const paths = buildPlatformSecretPaths("staging");
    expect(paths).toEqual([
      "/clearfin/staging/_platform/database-credentials",
      "/clearfin/staging/_platform/ai-api-keys",
      "/clearfin/staging/_platform/service-config",
    ]);
  });
});

// ── Tenant resource policy (Req 4.2) ─────────────────────────────────

describe("Tenant resource policy", () => {
  it("contains aws:PrincipalTag/tenant_id condition for tenant-abc", () => {
    const arn = "arn:aws:secretsmanager:il-central-1:123456789012:secret:/clearfin/dev/tenant-abc/bank-credentials";
    const policy = buildTenantResourcePolicy("tenant-abc", arn);

    expect(policy.Version).toBe("2012-10-17");
    expect(policy.Statement[0].Condition!["StringEquals"]["aws:PrincipalTag/tenant_id"]).toBe("tenant-abc");
    expect(policy.Statement[0].Resource).toBe(arn);
  });
});

// ── Platform resource policy (Req 4.8) ───────────────────────────────

describe("Platform resource policy", () => {
  it("allows only platform roles and denies tenant JIT credentials", () => {
    const roleArns = ["arn:aws:iam::123456789012:role/auth-service"];
    const arn = "arn:aws:secretsmanager:il-central-1:123456789012:secret:/clearfin/dev/_platform/database-credentials";
    const policy = buildPlatformResourcePolicy(roleArns, arn);

    expect(policy.Statement).toHaveLength(2);

    const allow = policy.Statement[0];
    expect(allow.Effect).toBe("Allow");
    expect(allow.Principal).toEqual({ AWS: roleArns });

    const deny = policy.Statement[1];
    expect(deny.Effect).toBe("Deny");
    expect(deny.Condition!["StringLike"]["aws:PrincipalTag/tenant_id"]).toEqual(["*"]);
  });
});

// ── Cross-tenant access denial (Req 4.5) ─────────────────────────────

describe("Cross-tenant access denial", () => {
  it("denies when path tenant differs from caller tenant", () => {
    const result = checkCrossTenantAccess("/clearfin/dev/tenant-abc/bank-credentials", "tenant-xyz");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("CROSS_TENANT_ACCESS_DENIED");
      expect(result.error.pathTenantId).toBe("tenant-abc");
      expect(result.error.callerTenantId).toBe("tenant-xyz");
    }
  });

  it("allows when path tenant matches caller tenant", () => {
    const result = checkCrossTenantAccess("/clearfin/dev/tenant-abc/bank-credentials", "tenant-abc");
    expect(result.ok).toBe(true);
  });

  it("allows access to _platform paths for any caller", () => {
    const result = checkCrossTenantAccess("/clearfin/dev/_platform/database-credentials", "tenant-abc");
    expect(result.ok).toBe(true);
  });

  it("logs CRITICAL on cross-tenant violation via manager", () => {
    const logs: string[] = [];
    const logger = createLogger("test", "corr", {}, (json) => logs.push(json));
    const { manager } = makeManager("dev");
    // Use a fresh manager with our logging logger
    const config: SecretsHierarchyConfig = { env: "dev", kmsKeyArn: "key", platformRoleArns: [] };
    const mgr = new SecretsHierarchyManager(config, makeMockClient(), logger);

    const result = mgr.validateAccess("/clearfin/dev/tenant-abc/config", "tenant-xyz");
    expect(result.ok).toBe(false);

    const criticalLog = logs.find((l) => l.includes("CRITICAL"));
    expect(criticalLog).toBeDefined();
    expect(criticalLog).toContain("Cross-tenant access violation");
  });
});

// ── provisionTenant (Req 4.1, 4.2, 4.3, 4.4) ───────────────────────

describe("provisionTenant", () => {
  it("creates three secrets with correct paths and KMS encryption", async () => {
    const { manager, client } = makeManager("prod");
    const result = await manager.provisionTenant("tenant-001", "prod");

    expect(result.ok).toBe(true);
    expect(client.createSecretCalls).toHaveLength(3);

    const names = client.createSecretCalls.map((c) => c.Name);
    expect(names).toContain("/clearfin/prod/tenant-001/bank-credentials");
    expect(names).toContain("/clearfin/prod/tenant-001/api-keys");
    expect(names).toContain("/clearfin/prod/tenant-001/config");

    // All use KMS key
    for (const call of client.createSecretCalls) {
      expect(call.KmsKeyId).toBe("arn:aws:kms:il-central-1:123456789012:key/test-key");
    }
  });

  it("tags each secret with tenant_id, environment, secret_type, created_by", async () => {
    const { manager, client } = makeManager("dev");
    await manager.provisionTenant("tenant-002", "dev");

    for (const call of client.createSecretCalls) {
      const tagMap = Object.fromEntries(call.Tags.map((t) => [t.Key, t.Value]));
      expect(tagMap["tenant_id"]).toBe("tenant-002");
      expect(tagMap["environment"]).toBe("dev");
      expect(tagMap["created_by"]).toBe("secrets-hierarchy-manager");
      expect(["bank-credentials", "api-keys", "config"]).toContain(tagMap["secret_type"]);
    }
  });

  it("returns error on createSecret failure", async () => {
    const { manager } = makeManager("dev", [], {
      createSecret: async () => { throw new Error("AWS error"); },
    });
    const result = await manager.provisionTenant("tenant-fail", "dev");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("PROVISION_FAILED");
    }
  });
});

// ── applyResourcePolicy (Req 4.2) ───────────────────────────────────

describe("applyResourcePolicy", () => {
  it("applies policy successfully", async () => {
    const { manager } = makeManager();
    const policy = buildTenantResourcePolicy("tenant-abc", "arn:test");
    const result = await manager.applyResourcePolicy("arn:test", policy);
    expect(result.ok).toBe(true);
  });

  it("returns error on failure", async () => {
    const { manager } = makeManager("dev", [], {
      putResourcePolicy: async () => { throw new Error("Policy error"); },
    });
    const policy = buildTenantResourcePolicy("tenant-abc", "arn:test");
    const result = await manager.applyResourcePolicy("arn:test", policy);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("POLICY_APPLY_FAILED");
    }
  });
});

// ── enableRotation (Req 4.3, 4.4) ───────────────────────────────────

describe("enableRotation", () => {
  it("enables 90-day rotation successfully", async () => {
    const { manager } = makeManager();
    const result = await manager.enableRotation("arn:test", 90);
    expect(result.ok).toBe(true);
  });

  it("returns error on rotation failure", async () => {
    const { manager } = makeManager("dev", [], {
      rotateSecret: async () => { throw new Error("Rotation error"); },
    });
    const result = await manager.enableRotation("arn:test", 90);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("ROTATION_CONFIG_FAILED");
      expect(result.error.intervalDays).toBe(90);
    }
  });
});

// ── tagSecret (Req 4.6) ─────────────────────────────────────────────

describe("tagSecret", () => {
  it("tags secret with all required metadata", async () => {
    const { manager } = makeManager();
    const tags: SecretTags = {
      tenant_id: "tenant-abc",
      environment: "dev",
      secret_type: "bank-credentials",
      created_by: "admin",
    };
    const result = await manager.tagSecret("arn:test", tags);
    expect(result.ok).toBe(true);
  });

  it("returns error on tag failure", async () => {
    const { manager } = makeManager("dev", [], {
      tagResource: async () => { throw new Error("Tag error"); },
    });
    const tags: SecretTags = {
      tenant_id: "tenant-abc",
      environment: "dev",
      secret_type: "config",
      created_by: "admin",
    };
    const result = await manager.tagSecret("arn:test", tags);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("TAG_FAILED");
    }
  });
});

// ── provisionPlatformSecrets (Req 4.7, 4.8, 4.9, 4.10) ─────────────

describe("provisionPlatformSecrets", () => {
  it("creates three platform secrets with correct paths", async () => {
    const { manager, client } = makeManager("prod", ["arn:aws:iam::123456789012:role/auth-service"]);
    const result = await manager.provisionPlatformSecrets("prod");

    expect(result.ok).toBe(true);
    expect(client.createSecretCalls).toHaveLength(3);

    const names = client.createSecretCalls.map((c) => c.Name);
    expect(names).toContain("/clearfin/prod/_platform/database-credentials");
    expect(names).toContain("/clearfin/prod/_platform/ai-api-keys");
    expect(names).toContain("/clearfin/prod/_platform/service-config");
  });

  it("tags platform secrets with _platform tenant_id", async () => {
    const { manager, client } = makeManager("dev", ["arn:aws:iam::123456789012:role/auth-service"]);
    await manager.provisionPlatformSecrets("dev");

    for (const call of client.createSecretCalls) {
      const tagMap = Object.fromEntries(call.Tags.map((t) => [t.Key, t.Value]));
      expect(tagMap["tenant_id"]).toBe("_platform");
      expect(tagMap["environment"]).toBe("dev");
      expect(tagMap["created_by"]).toBe("secrets-hierarchy-manager");
    }
  });

  it("returns error on createSecret failure", async () => {
    const { manager } = makeManager("dev", [], {
      createSecret: async () => { throw new Error("AWS error"); },
    });
    const result = await manager.provisionPlatformSecrets("dev");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("PROVISION_FAILED");
    }
  });
});
