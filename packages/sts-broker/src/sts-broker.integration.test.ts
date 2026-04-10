// Integration test: STS Broker full JIT credential issuance flow
// Tests: service identity verification → tenant validation → session policy build
//        → STS AssumeRole → return JIT credential
// Requirements: 3.1–3.7

import { describe, it, expect } from "vitest";
import { createLogger } from "@clearfin/shared";
import {
  STSBroker,
  type STSClient,
  type ServiceRegistry,
  type TenantStore,
  type STSBrokerConfig,
} from "./sts-broker.js";

// ── Mock factories ───────────────────────────────────────────────────

function createMockSTSClient(): STSClient {
  return {
    async assumeRole(input) {
      return {
        Credentials: {
          AccessKeyId: "AKIAIOSFODNN7EXAMPLE",
          SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
          SessionToken: "FwoGZXIvYXdzEBYaDH...",
          Expiration: new Date(Date.now() + input.DurationSeconds * 1000),
        },
      };
    },
  };
}

function createFailingSTSClient(errorMsg: string): STSClient {
  return {
    async assumeRole() {
      throw new Error(errorMsg);
    },
  };
}

function createServiceRegistry(registered: string[]): ServiceRegistry {
  const set = new Set(registered);
  return { isRegistered: (name) => set.has(name) };
}

function createTenantStore(existing: string[]): TenantStore {
  const set = new Set(existing);
  return { exists: (id) => set.has(id) };
}

const BASE_CONFIG: STSBrokerConfig = {
  env: "prod",
  roleArn: "arn:aws:iam::123456789012:role/clearfin-sts-base-role",
};

function makeBroker(opts?: {
  stsClient?: STSClient;
  registeredServices?: string[];
  existingTenants?: string[];
}) {
  const logger = createLogger("sts-broker-integration", "test-corr", {}, () => {});
  return new STSBroker(
    BASE_CONFIG,
    opts?.stsClient ?? createMockSTSClient(),
    createServiceRegistry(opts?.registeredServices ?? ["auth-service", "sts-broker", "secrets-manager"]),
    createTenantStore(opts?.existingTenants ?? ["tenant-001", "tenant-002"]),
    logger,
  );
}

// ── Integration Tests ────────────────────────────────────────────────

describe("STS Broker Integration: full JIT credential flow", () => {
  it("issues a JIT credential for a valid service and tenant", async () => {
    const broker = makeBroker();

    const result = await broker.issueCredential(
      "tenant-001",
      "auth-service",
      "secretsmanager:GetSecretValue",
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;

    const cred = result.value;
    expect(cred.accessKeyId).toBe("AKIAIOSFODNN7EXAMPLE");
    expect(cred.tenantId).toBe("tenant-001");
    expect(cred.serviceName).toBe("auth-service");
    expect(cred.roleSessionName).toBe("tenant-001-auth-service");
    expect(cred.expiration.getTime()).toBeGreaterThan(Date.now());
  });

  it("scopes session policy to the correct tenant path", () => {
    const broker = makeBroker();
    const policy = broker.buildSessionPolicy("tenant-002", "secretsmanager:GetSecretValue");

    expect(policy.Version).toBe("2012-10-17");
    expect(policy.Statement).toHaveLength(1);
    expect(policy.Statement[0].Resource).toBe(
      "arn:aws:secretsmanager:*:*:secret:/clearfin/prod/tenant-002/*",
    );
    expect(policy.Statement[0].Action).toEqual(["secretsmanager:GetSecretValue"]);
  });

  it("rejects unregistered service with SERVICE_NOT_REGISTERED", async () => {
    const broker = makeBroker();

    const result = await broker.issueCredential(
      "tenant-001",
      "unknown-service",
      "secretsmanager:GetSecretValue",
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe("SERVICE_NOT_REGISTERED");
  });

  it("rejects non-existent tenant with TENANT_NOT_FOUND", async () => {
    const broker = makeBroker();

    const result = await broker.issueCredential(
      "tenant-nonexistent",
      "auth-service",
      "secretsmanager:GetSecretValue",
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe("TENANT_NOT_FOUND");
  });

  it("returns STS_ASSUME_ROLE_FAILED when STS call fails", async () => {
    const broker = makeBroker({
      stsClient: createFailingSTSClient("AccessDenied"),
    });

    const result = await broker.issueCredential(
      "tenant-001",
      "auth-service",
      "secretsmanager:GetSecretValue",
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe("STS_ASSUME_ROLE_FAILED");
    if (result.error.code === "STS_ASSUME_ROLE_FAILED") {
      expect(result.error.tenantId).toBe("tenant-001");
    }
  });

  it("issues credentials for multiple tenants with isolated policies", async () => {
    const broker = makeBroker();

    const result1 = await broker.issueCredential(
      "tenant-001",
      "auth-service",
      "secretsmanager:GetSecretValue",
    );
    const result2 = await broker.issueCredential(
      "tenant-002",
      "auth-service",
      "secretsmanager:GetSecretValue",
    );

    expect(result1.ok).toBe(true);
    expect(result2.ok).toBe(true);
    if (!result1.ok || !result2.ok) return;

    // Verify different role session names
    expect(result1.value.roleSessionName).toBe("tenant-001-auth-service");
    expect(result2.value.roleSessionName).toBe("tenant-002-auth-service");

    // Verify policies scope to different tenants
    const policy1 = broker.buildSessionPolicy("tenant-001", "secretsmanager:GetSecretValue");
    const policy2 = broker.buildSessionPolicy("tenant-002", "secretsmanager:GetSecretValue");
    expect(policy1.Statement[0].Resource).toContain("tenant-001");
    expect(policy2.Statement[0].Resource).toContain("tenant-002");
    expect(policy1.Statement[0].Resource).not.toContain("tenant-002");
  });
});
