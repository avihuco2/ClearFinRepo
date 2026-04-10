// Integration test: Secrets Hierarchy Manager provisioning and access control
// Tests: tenant provisioning, platform provisioning, cross-tenant denial, rotation, tagging
// Requirements: 4.1–4.10

import { describe, it, expect } from "vitest";
import { createLogger } from "@clearfin/shared";
import {
  SecretsHierarchyManager,
  type SecretsManagerClient,
  type SecretsHierarchyConfig,
  type CreateSecretInput,
  type CreateSecretOutput,
  type PutResourcePolicyInput,
  checkCrossTenantAccess,
  buildTenantSecretPaths,
  buildPlatformSecretPaths,
} from "./secrets-hierarchy-manager.js";

// ── Mock factory ─────────────────────────────────────────────────────

interface MockSecretsManagerClient extends SecretsManagerClient {
  createdSecrets: CreateSecretInput[];
  appliedPolicies: PutResourcePolicyInput[];
  rotatedSecrets: Array<{ SecretId: string; days: number }>;
  taggedSecrets: Array<{ SecretId: string; tags: Array<{ Key: string; Value: string }> }>;
}

function createMockSecretsClient(): MockSecretsManagerClient {
  const createdSecrets: CreateSecretInput[] = [];
  const appliedPolicies: PutResourcePolicyInput[] = [];
  const rotatedSecrets: Array<{ SecretId: string; days: number }> = [];
  const taggedSecrets: Array<{ SecretId: string; tags: Array<{ Key: string; Value: string }> }> = [];

  return {
    createdSecrets,
    appliedPolicies,
    rotatedSecrets,
    taggedSecrets,
    async createSecret(input) {
      createdSecrets.push(input);
      return { ARN: `arn:aws:secretsmanager:il-central-1:123456789012:secret:${input.Name}`, Name: input.Name };
    },
    async putResourcePolicy(input) {
      appliedPolicies.push(input);
    },
    async rotateSecret(input) {
      rotatedSecrets.push({ SecretId: input.SecretId, days: input.RotationRules.AutomaticallyAfterDays });
    },
    async tagResource(input) {
      taggedSecrets.push({ SecretId: input.SecretId, tags: input.Tags });
    },
  };
}

const CONFIG: SecretsHierarchyConfig = {
  env: "prod",
  kmsKeyArn: "arn:aws:kms:il-central-1:123456789012:key/test-key-id",
  platformRoleArns: [
    "arn:aws:iam::123456789012:role/clearfin-auth-service",
    "arn:aws:iam::123456789012:role/clearfin-sts-broker",
  ],
};

function makeManager(client?: MockSecretsManagerClient) {
  const logger = createLogger("secrets-integration", "test-corr", {}, () => {});
  const mockClient = client ?? createMockSecretsClient();
  const manager = new SecretsHierarchyManager(CONFIG, mockClient, logger);
  return { manager, client: mockClient };
}

// ── Integration Tests ────────────────────────────────────────────────

describe("Secrets Hierarchy Manager Integration", () => {
  it("provisions tenant secrets at correct paths with encryption and rotation", async () => {
    const { manager, client } = makeManager();

    const result = await manager.provisionTenant("tenant-001", "prod");
    expect(result.ok).toBe(true);

    // Verify 3 secrets created at correct paths
    expect(client.createdSecrets).toHaveLength(3);
    const paths = client.createdSecrets.map((s) => s.Name);
    expect(paths).toContain("/clearfin/prod/tenant-001/bank-credentials");
    expect(paths).toContain("/clearfin/prod/tenant-001/api-keys");
    expect(paths).toContain("/clearfin/prod/tenant-001/config");

    // Verify KMS encryption
    for (const secret of client.createdSecrets) {
      expect(secret.KmsKeyId).toBe(CONFIG.kmsKeyArn);
    }

    // Verify rotation enabled (90-day interval)
    expect(client.rotatedSecrets).toHaveLength(3);
    for (const rotation of client.rotatedSecrets) {
      expect(rotation.days).toBe(90);
    }

    // Verify resource policies applied
    expect(client.appliedPolicies).toHaveLength(3);
    for (const policy of client.appliedPolicies) {
      const parsed = JSON.parse(policy.ResourcePolicy);
      expect(parsed.Statement[0].Condition.StringEquals["aws:PrincipalTag/tenant_id"]).toBe("tenant-001");
    }

    // Verify tags
    for (const secret of client.createdSecrets) {
      const tagMap = Object.fromEntries(secret.Tags.map((t) => [t.Key, t.Value]));
      expect(tagMap.tenant_id).toBe("tenant-001");
      expect(tagMap.environment).toBe("prod");
      expect(tagMap.created_by).toBe("secrets-hierarchy-manager");
    }
  });

  it("provisions platform secrets with platform resource policy", async () => {
    const { manager, client } = makeManager();

    const result = await manager.provisionPlatformSecrets("prod");
    expect(result.ok).toBe(true);

    // Verify 3 platform secrets created
    expect(client.createdSecrets).toHaveLength(3);
    const paths = client.createdSecrets.map((s) => s.Name);
    expect(paths).toContain("/clearfin/prod/_platform/database-credentials");
    expect(paths).toContain("/clearfin/prod/_platform/ai-api-keys");
    expect(paths).toContain("/clearfin/prod/_platform/service-config");

    // Verify platform resource policy denies tenant JIT credentials
    for (const policy of client.appliedPolicies) {
      const parsed = JSON.parse(policy.ResourcePolicy);
      const denyStatement = parsed.Statement.find((s: any) => s.Effect === "Deny");
      expect(denyStatement).toBeDefined();
      expect(denyStatement.Condition.StringLike["aws:PrincipalTag/tenant_id"]).toEqual(["*"]);
    }

    // Verify platform tags
    for (const secret of client.createdSecrets) {
      const tagMap = Object.fromEntries(secret.Tags.map((t) => [t.Key, t.Value]));
      expect(tagMap.tenant_id).toBe("_platform");
    }
  });

  it("denies cross-tenant access when path tenant differs from caller", () => {
    const result = checkCrossTenantAccess(
      "/clearfin/prod/tenant-001/bank-credentials",
      "tenant-002",
    );
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe("CROSS_TENANT_ACCESS_DENIED");
    expect(result.error.pathTenantId).toBe("tenant-001");
    expect(result.error.callerTenantId).toBe("tenant-002");
  });

  it("allows access when path tenant matches caller tenant", () => {
    const result = checkCrossTenantAccess(
      "/clearfin/prod/tenant-001/bank-credentials",
      "tenant-001",
    );
    expect(result.ok).toBe(true);
  });

  it("allows platform path access (no cross-tenant check for _platform)", () => {
    const result = checkCrossTenantAccess(
      "/clearfin/prod/_platform/database-credentials",
      "tenant-001",
    );
    expect(result.ok).toBe(true);
  });

  it("constructs correct tenant and platform paths", () => {
    const tenantPaths = buildTenantSecretPaths("staging", "tenant-xyz");
    expect(tenantPaths).toEqual([
      "/clearfin/staging/tenant-xyz/bank-credentials",
      "/clearfin/staging/tenant-xyz/api-keys",
      "/clearfin/staging/tenant-xyz/config",
    ]);

    const platformPaths = buildPlatformSecretPaths("staging");
    expect(platformPaths).toEqual([
      "/clearfin/staging/_platform/database-credentials",
      "/clearfin/staging/_platform/ai-api-keys",
      "/clearfin/staging/_platform/service-config",
    ]);
  });
});
