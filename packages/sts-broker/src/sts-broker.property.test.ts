// Property-based tests for STS_Broker
// Uses fast-check for property testing, vitest as runner

import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { STSBroker } from "./sts-broker.js";
import type { STSClient, ServiceRegistry, TenantStore, STSBrokerConfig } from "./sts-broker.js";
import { createLogger } from "@clearfin/shared";

// ── Helpers ──────────────────────────────────────────────────────────

const noop = () => {};
const silentLogger = createLogger("sts-broker-test", "test-corr-id", {}, noop);

function makeBroker(
  env: string,
  registeredServices: string[] = [],
  existingTenants: string[] = [],
): STSBroker {
  const config: STSBrokerConfig = { env, roleArn: "arn:aws:iam::123456789012:role/test-role" };
  const stsClient: STSClient = {
    assumeRole: async () => ({
      Credentials: {
        AccessKeyId: "AKIA_TEST",
        SecretAccessKey: "secret",
        SessionToken: "token",
        Expiration: new Date(),
      },
    }),
  };
  const serviceRegistry: ServiceRegistry = {
    isRegistered: (name) => registeredServices.includes(name),
  };
  const tenantStore: TenantStore = {
    exists: (id) => existingTenants.includes(id),
  };
  return new STSBroker(config, stsClient, serviceRegistry, tenantStore, silentLogger);
}

// Generators
const tenantIdArb = fc.stringMatching(/^[a-zA-Z0-9_-]{1,64}$/);
const serviceNameArb = fc.stringMatching(/^[a-zA-Z0-9_-]{1,64}$/);
const actionArb = fc.stringMatching(/^[a-z]+:[A-Za-z]+$/);
const envArb = fc.constantFrom("dev", "staging", "prod");

// ── Property 9: STS Request Construction ─────────────────────────────
// **Validates: Requirements 3.1, 3.3, 3.7**

describe("Property 9: STS Request Construction", () => {
  it("session policy Resource matches arn:aws:secretsmanager:*:*:secret:/clearfin/{env}/{tenantId}/*", () => {
    fc.assert(
      fc.property(tenantIdArb, actionArb, envArb, (tenantId, action, env) => {
        const broker = makeBroker(env);
        const policy = broker.buildSessionPolicy(tenantId, action);

        expect(policy.Version).toBe("2012-10-17");
        expect(policy.Statement).toHaveLength(1);
        expect(policy.Statement[0].Effect).toBe("Allow");
        expect(policy.Statement[0].Action).toEqual([action]);
        expect(policy.Statement[0].Resource).toBe(
          `arn:aws:secretsmanager:*:*:secret:/clearfin/${env}/${tenantId}/*`,
        );
      }),
      { numRuns: 100 },
    );
  });

  it("RoleSessionName contains both tenantId and serviceName", () => {
    fc.assert(
      fc.property(tenantIdArb, serviceNameArb, (tenantId, serviceName) => {
        const broker = makeBroker("dev");
        const roleSessionName = broker.buildRoleSessionName(tenantId, serviceName);

        expect(roleSessionName).toContain(tenantId);
        expect(roleSessionName).toContain(serviceName);
        expect(roleSessionName).toBe(`${tenantId}-${serviceName}`);
      }),
      { numRuns: 100 },
    );
  });
});

// ── Property 10: Service Identity Verification ───────────────────────
// **Validates: Requirements 3.5**

describe("Property 10: Service Identity Verification", () => {
  it("accepts registered services and rejects unregistered ones", () => {
    fc.assert(
      fc.property(
        fc.uniqueArray(serviceNameArb, { minLength: 1, maxLength: 10 }),
        serviceNameArb,
        (registeredServices, queryService) => {
          const broker = makeBroker("dev", registeredServices);
          const result = broker.verifyServiceIdentity(queryService);

          if (registeredServices.includes(queryService)) {
            expect(result.ok).toBe(true);
          } else {
            expect(result.ok).toBe(false);
            if (!result.ok && result.error.code === "SERVICE_NOT_REGISTERED") {
              expect(result.error.serviceName).toBe(queryService);
            }
          }
        },
      ),
      { numRuns: 100 },
    );
  });
});

// ── Property 11: Non-Existent Tenant Rejection ──────────────────────
// **Validates: Requirements 3.6**

describe("Property 11: Non-Existent Tenant Rejection", () => {
  it("rejects non-existent tenants with TENANT_NOT_FOUND and accepts existing ones", () => {
    fc.assert(
      fc.property(
        fc.uniqueArray(tenantIdArb, { minLength: 1, maxLength: 10 }),
        tenantIdArb,
        (existingTenants, queryTenant) => {
          const broker = makeBroker("dev", [], existingTenants);
          const result = broker.validateTenantExists(queryTenant);

          if (existingTenants.includes(queryTenant)) {
            expect(result.ok).toBe(true);
          } else {
            expect(result.ok).toBe(false);
            if (!result.ok && result.error.code === "TENANT_NOT_FOUND") {
              expect(result.error.tenantId).toBe(queryTenant);
            }
          }
        },
      ),
      { numRuns: 100 },
    );
  });
});
