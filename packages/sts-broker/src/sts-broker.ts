// @clearfin/sts-broker — JIT AWS STS credential issuance scoped to tenants

import {
  type STSSessionPolicy,
  type JITCredential,
  type Result,
  ok,
  err,
} from "@clearfin/shared";
import { type Logger } from "@clearfin/shared";

// ── Error types ──────────────────────────────────────────────────────

export type STSError =
  | { code: "SERVICE_NOT_REGISTERED"; serviceName: string }
  | { code: "TENANT_NOT_FOUND"; tenantId: string }
  | { code: "STS_ASSUME_ROLE_FAILED"; roleArn: string; tenantId: string; awsErrorCode: string };

// ── Dependency interfaces ────────────────────────────────────────────

export interface AssumeRoleInput {
  RoleArn: string;
  RoleSessionName: string;
  DurationSeconds: number;
  Policy: string;
}

export interface AssumeRoleOutput {
  Credentials: {
    AccessKeyId: string;
    SecretAccessKey: string;
    SessionToken: string;
    Expiration: Date;
  };
}

export interface STSClient {
  assumeRole(input: AssumeRoleInput): Promise<AssumeRoleOutput>;
}

export interface ServiceRegistry {
  isRegistered(serviceName: string): boolean;
}

export interface TenantStore {
  exists(tenantId: string): boolean;
}

// ── Configuration ────────────────────────────────────────────────────

export interface STSBrokerConfig {
  env: string;
  roleArn: string;
}

// ── STS Broker ───────────────────────────────────────────────────────

export class STSBroker {
  constructor(
    private readonly config: STSBrokerConfig,
    private readonly stsClient: STSClient,
    private readonly serviceRegistry: ServiceRegistry,
    private readonly tenantStore: TenantStore,
    private readonly logger: Logger,
  ) {}

  /**
   * Task 6.1: Build IAM session policy scoped to a tenant's Secrets Manager paths.
   * Resource: arn:aws:secretsmanager:*:*:secret:/clearfin/{env}/{tenantId}/*
   */
  buildSessionPolicy(tenantId: string, action: string): STSSessionPolicy {
    return {
      Version: "2012-10-17",
      Statement: [
        {
          Effect: "Allow",
          Action: [action],
          Resource: `arn:aws:secretsmanager:*:*:secret:/clearfin/${this.config.env}/${tenantId}/*`,
        },
      ],
    };
  }

  /**
   * Task 6.3: Build RoleSessionName in format {tenantId}-{serviceName}.
   */
  buildRoleSessionName(tenantId: string, serviceName: string): string {
    return `${tenantId}-${serviceName}`;
  }

  /**
   * Task 6.4: Verify service identity against the platform service registry.
   */
  verifyServiceIdentity(serviceName: string): Result<void, STSError> {
    if (!this.serviceRegistry.isRegistered(serviceName)) {
      this.logger.warn("Unregistered service attempted credential request", {
        serviceName,
      });
      return err({ code: "SERVICE_NOT_REGISTERED", serviceName });
    }
    return ok(undefined);
  }

  /**
   * Task 6.6: Validate tenant existence. Reject with TENANT_NOT_FOUND and security alert.
   */
  validateTenantExists(tenantId: string): Result<void, STSError> {
    if (!this.tenantStore.exists(tenantId)) {
      this.logger.alert("JIT credential requested for non-existent tenant", {
        tenantId,
      });
      return err({ code: "TENANT_NOT_FOUND", tenantId });
    }
    return ok(undefined);
  }

  /**
   * Task 6.8: Full JIT credential issuance flow.
   * 1. Verify service identity
   * 2. Validate tenant exists
   * 3. Build session policy
   * 4. Call STS AssumeRole with 900s max duration
   * 5. Return JITCredential or structured error
   */
  async issueCredential(
    tenantId: string,
    serviceName: string,
    action: string,
  ): Promise<Result<JITCredential, STSError>> {
    // Step 1: Verify service identity
    const serviceCheck = this.verifyServiceIdentity(serviceName);
    if (!serviceCheck.ok) return serviceCheck;

    // Step 2: Validate tenant exists
    const tenantCheck = this.validateTenantExists(tenantId);
    if (!tenantCheck.ok) return tenantCheck;

    // Step 3: Build session policy
    const sessionPolicy = this.buildSessionPolicy(tenantId, action);
    const roleSessionName = this.buildRoleSessionName(tenantId, serviceName);

    // Step 4: Call STS AssumeRole
    try {
      const response = await this.stsClient.assumeRole({
        RoleArn: this.config.roleArn,
        RoleSessionName: roleSessionName,
        DurationSeconds: 900,
        Policy: JSON.stringify(sessionPolicy),
      });

      const credential: JITCredential = {
        accessKeyId: response.Credentials.AccessKeyId,
        secretAccessKey: response.Credentials.SecretAccessKey,
        sessionToken: response.Credentials.SessionToken,
        expiration: response.Credentials.Expiration,
        tenantId,
        serviceName,
        roleSessionName,
      };

      this.logger.info("JIT credential issued", { tenantId, serviceName, roleSessionName });
      return ok(credential);
    } catch (error: unknown) {
      const awsErrorCode = error instanceof Error ? error.message : "UNKNOWN";
      this.logger.error("STS AssumeRole failed", {
        roleArn: this.config.roleArn,
        tenantId,
        awsErrorCode,
      });
      return err({
        code: "STS_ASSUME_ROLE_FAILED",
        roleArn: this.config.roleArn,
        tenantId,
        awsErrorCode,
      });
    }
  }
}
