// Unit tests for STS_Broker
// Validates: Requirements 3.1-3.7

import { describe, it, expect, vi } from "vitest";
import { STSBroker } from "./sts-broker.js";
import type { STSClient, ServiceRegistry, TenantStore, STSBrokerConfig } from "./sts-broker.js";
import { createLogger } from "@clearfin/shared";

// ── Test helpers ─────────────────────────────────────────────────────

const noop = () => {};
const silentLogger = createLogger("sts-broker-test", "test-corr-id", {}, noop);

const defaultConfig: STSBrokerConfig = {
  env: "prod",
  roleArn: "arn:aws:iam::123456789012:role/clearfin-base-role",
};

const registeredServices = ["auth-service", "sts-broker", "secrets-hierarchy-manager"];
const existingTenants = ["tenant-abc", "tenant-xyz"];

function makeStsClient(overrides?: Partial<STSClient>): STSClient {
  return {
    assumeRole: overrides?.assumeRole ?? (async (input) => ({
      Credentials: {
        AccessKeyId: "AKIAIOSFODNN7EXAMPLE",
        SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        SessionToken: "FwoGZXIvYXdzEBY_session_token",
        Expiration: new Date("2025-01-01T00:15:00Z"),
      },
    })),
  };
}

function makeBroker(opts?: {
  config?: STSBrokerConfig;
  stsClient?: STSClient;
  services?: string[];
  tenants?: string[];
  logger?: ReturnType<typeof createLogger>;
}): STSBroker {
  const registry: ServiceRegistry = {
    isRegistered: (name) => (opts?.services ?? registeredServices).includes(name),
  };
  const tenantStore: TenantStore = {
    exists: (id) => (opts?.tenants ?? existingTenants).includes(id),
  };
  return new STSBroker(
    opts?.config ?? defaultConfig,
    opts?.stsClient ?? makeStsClient(),
    registry,
    tenantStore,
    opts?.logger ?? silentLogger,
  );
}

// ── 6.1: Session policy construction ─────────────────────────────────

describe("buildSessionPolicy", () => {
  it("scopes Resource to the correct tenant path", () => {
    const broker = makeBroker();
    const policy = broker.buildSessionPolicy("tenant-abc", "secretsmanager:GetSecretValue");

    expect(policy.Version).toBe("2012-10-17");
    expect(policy.Statement).toHaveLength(1);
    expect(policy.Statement[0].Resource).toBe(
      "arn:aws:secretsmanager:*:*:secret:/clearfin/prod/tenant-abc/*",
    );
    expect(policy.Statement[0].Action).toEqual(["secretsmanager:GetSecretValue"]);
    expect(policy.Statement[0].Effect).toBe("Allow");
  });

  it("uses the configured environment in the resource ARN", () => {
    const broker = makeBroker({ config: { ...defaultConfig, env: "staging" } });
    const policy = broker.buildSessionPolicy("tenant-xyz", "secretsmanager:PutSecretValue");

    expect(policy.Statement[0].Resource).toBe(
      "arn:aws:secretsmanager:*:*:secret:/clearfin/staging/tenant-xyz/*",
    );
  });
});

// ── 6.3: RoleSessionName formatting ──────────────────────────────────

describe("buildRoleSessionName", () => {
  it("formats as {tenantId}-{serviceName}", () => {
    const broker = makeBroker();
    expect(broker.buildRoleSessionName("tenant-abc", "auth-service")).toBe(
      "tenant-abc-auth-service",
    );
  });

  it("includes both tenant and service identifiers", () => {
    const broker = makeBroker();
    const name = broker.buildRoleSessionName("t-123", "sts-broker");
    expect(name).toContain("t-123");
    expect(name).toContain("sts-broker");
  });
});

// ── 6.4: Service identity verification ───────────────────────────────

describe("verifyServiceIdentity", () => {
  it("accepts a registered service", () => {
    const broker = makeBroker();
    const result = broker.verifyServiceIdentity("auth-service");
    expect(result.ok).toBe(true);
  });

  it("rejects an unregistered service with SERVICE_NOT_REGISTERED", () => {
    const broker = makeBroker();
    const result = broker.verifyServiceIdentity("rogue-service");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("SERVICE_NOT_REGISTERED");
      expect(result.error.serviceName).toBe("rogue-service");
    }
  });
});

// ── 6.6: Tenant existence validation ─────────────────────────────────

describe("validateTenantExists", () => {
  it("accepts an existing tenant", () => {
    const broker = makeBroker();
    const result = broker.validateTenantExists("tenant-abc");
    expect(result.ok).toBe(true);
  });

  it("rejects a non-existent tenant with TENANT_NOT_FOUND", () => {
    const broker = makeBroker();
    const result = broker.validateTenantExists("ghost-tenant");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("TENANT_NOT_FOUND");
      expect(result.error.tenantId).toBe("ghost-tenant");
    }
  });

  it("logs a security alert for non-existent tenant", () => {
    const logs: string[] = [];
    const logger = createLogger("sts-broker-test", "corr-id", {}, (json) => logs.push(json));
    const broker = makeBroker({ logger });

    broker.validateTenantExists("ghost-tenant");

    const alertLog = logs.find((l) => l.includes('"level":"ALERT"'));
    expect(alertLog).toBeDefined();
    expect(alertLog).toContain("ghost-tenant");
  });
});

// ── 6.8: Full JIT credential flow ───────────────────────────────────

describe("issueCredential", () => {
  it("returns a JITCredential on success", async () => {
    const broker = makeBroker();
    const result = await broker.issueCredential(
      "tenant-abc",
      "auth-service",
      "secretsmanager:GetSecretValue",
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.tenantId).toBe("tenant-abc");
      expect(result.value.serviceName).toBe("auth-service");
      expect(result.value.roleSessionName).toBe("tenant-abc-auth-service");
      expect(result.value.accessKeyId).toBeDefined();
      expect(result.value.secretAccessKey).toBeDefined();
      expect(result.value.sessionToken).toBeDefined();
      expect(result.value.expiration).toBeInstanceOf(Date);
    }
  });

  it("rejects unregistered service before calling STS", async () => {
    const assumeRole = vi.fn();
    const broker = makeBroker({ stsClient: { assumeRole } });

    const result = await broker.issueCredential(
      "tenant-abc",
      "rogue-service",
      "secretsmanager:GetSecretValue",
    );

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe("SERVICE_NOT_REGISTERED");
    expect(assumeRole).not.toHaveBeenCalled();
  });

  it("rejects non-existent tenant before calling STS", async () => {
    const assumeRole = vi.fn();
    const broker = makeBroker({ stsClient: { assumeRole } });

    const result = await broker.issueCredential(
      "ghost-tenant",
      "auth-service",
      "secretsmanager:GetSecretValue",
    );

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error.code).toBe("TENANT_NOT_FOUND");
    expect(assumeRole).not.toHaveBeenCalled();
  });

  it("passes 900-second duration to STS AssumeRole", async () => {
    const assumeRole = vi.fn().mockResolvedValue({
      Credentials: {
        AccessKeyId: "AK",
        SecretAccessKey: "SK",
        SessionToken: "ST",
        Expiration: new Date(),
      },
    });
    const broker = makeBroker({ stsClient: { assumeRole } });

    await broker.issueCredential("tenant-abc", "auth-service", "secretsmanager:GetSecretValue");

    expect(assumeRole).toHaveBeenCalledWith(
      expect.objectContaining({ DurationSeconds: 900 }),
    );
  });

  it("passes the correct session policy JSON to STS", async () => {
    const assumeRole = vi.fn().mockResolvedValue({
      Credentials: {
        AccessKeyId: "AK",
        SecretAccessKey: "SK",
        SessionToken: "ST",
        Expiration: new Date(),
      },
    });
    const broker = makeBroker({ stsClient: { assumeRole } });

    await broker.issueCredential("tenant-abc", "auth-service", "secretsmanager:GetSecretValue");

    const call = assumeRole.mock.calls[0][0];
    const policy = JSON.parse(call.Policy);
    expect(policy.Statement[0].Resource).toBe(
      "arn:aws:secretsmanager:*:*:secret:/clearfin/prod/tenant-abc/*",
    );
  });

  it("returns STS_ASSUME_ROLE_FAILED on STS error", async () => {
    const assumeRole = vi.fn().mockRejectedValue(new Error("AccessDenied"));
    const broker = makeBroker({ stsClient: { assumeRole } });

    const result = await broker.issueCredential(
      "tenant-abc",
      "auth-service",
      "secretsmanager:GetSecretValue",
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("STS_ASSUME_ROLE_FAILED");
      expect(result.error.roleArn).toBe(defaultConfig.roleArn);
      expect(result.error.tenantId).toBe("tenant-abc");
      expect(result.error.awsErrorCode).toBe("AccessDenied");
    }
  });

  it("logs failure with role ARN, tenantId, and error code on STS error", async () => {
    const logs: string[] = [];
    const logger = createLogger("sts-broker-test", "corr-id", {}, (json) => logs.push(json));
    const assumeRole = vi.fn().mockRejectedValue(new Error("ExpiredTokenException"));
    const broker = makeBroker({ stsClient: { assumeRole }, logger });

    await broker.issueCredential("tenant-abc", "auth-service", "secretsmanager:GetSecretValue");

    const errorLog = logs.find((l) => l.includes('"level":"ERROR"'));
    expect(errorLog).toBeDefined();
    expect(errorLog).toContain(defaultConfig.roleArn);
    expect(errorLog).toContain("tenant-abc");
    expect(errorLog).toContain("ExpiredTokenException");
  });
});
