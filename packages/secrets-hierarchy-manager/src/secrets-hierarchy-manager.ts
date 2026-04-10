// @clearfin/secrets-hierarchy-manager — AWS Secrets Manager hierarchy provisioning and management

import {
  type SecretTags,
  type Result,
  ok,
  err,
} from "@clearfin/shared";
import { type Logger } from "@clearfin/shared";

// ── Error types ──────────────────────────────────────────────────────

export type ProvisionError =
  | { code: "PROVISION_FAILED"; secretPath: string; reason: string }
  | { code: "KMS_ENCRYPTION_FAILED"; kmsKeyArn: string; secretPath: string };

export type PolicyError = { code: "POLICY_APPLY_FAILED"; secretArn: string; reason: string };

export type RotationError = { code: "ROTATION_CONFIG_FAILED"; secretArn: string; intervalDays: number; reason: string };

export type TagError = { code: "TAG_FAILED"; secretArn: string; reason: string };

export type AccessDeniedError = { code: "CROSS_TENANT_ACCESS_DENIED"; pathTenantId: string; callerTenantId: string };

// ── Dependency interfaces ────────────────────────────────────────────

export interface CreateSecretInput {
  Name: string;
  KmsKeyId: string;
  Tags: Array<{ Key: string; Value: string }>;
  SecretString?: string;
}

export interface CreateSecretOutput {
  ARN: string;
  Name: string;
}

export interface PutResourcePolicyInput {
  SecretId: string;
  ResourcePolicy: string;
}

export interface RotateSecretInput {
  SecretId: string;
  RotationRules: { AutomaticallyAfterDays: number };
}

export interface TagResourceInput {
  SecretId: string;
  Tags: Array<{ Key: string; Value: string }>;
}

export interface SecretsManagerClient {
  createSecret(input: CreateSecretInput): Promise<CreateSecretOutput>;
  putResourcePolicy(input: PutResourcePolicyInput): Promise<void>;
  rotateSecret(input: RotateSecretInput): Promise<void>;
  tagResource(input: TagResourceInput): Promise<void>;
}

// ── Configuration ────────────────────────────────────────────────────

export interface SecretsHierarchyConfig {
  env: string;
  kmsKeyArn: string;
  platformRoleArns: string[];
}

// ── Constants ────────────────────────────────────────────────────────

const TENANT_SECRET_TYPES = ["bank-credentials", "api-keys", "config"] as const;
const PLATFORM_SECRET_TYPES = ["database-credentials", "ai-api-keys", "service-config"] as const;
const DEFAULT_ROTATION_DAYS = 90;

// ── Path helpers ─────────────────────────────────────────────────────

export function buildTenantSecretPaths(env: string, tenantId: string): string[] {
  return TENANT_SECRET_TYPES.map(
    (type) => `/clearfin/${env}/${tenantId}/${type}`,
  );
}

export function buildPlatformSecretPaths(env: string): string[] {
  return PLATFORM_SECRET_TYPES.map(
    (type) => `/clearfin/${env}/_platform/${type}`,
  );
}

// ── Policy builders ──────────────────────────────────────────────────

export interface ResourcePolicy {
  Version: "2012-10-17";
  Statement: Array<{
    Sid: string;
    Effect: "Allow" | "Deny";
    Principal: { AWS: string | string[] } | "*";
    Action: string | string[];
    Resource: string;
    Condition?: Record<string, Record<string, string | string[]>>;
  }>;
}

export function buildTenantResourcePolicy(tenantId: string, secretArn: string): ResourcePolicy {
  return {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "AllowTenantAccess",
        Effect: "Allow",
        Principal: "*",
        Action: "secretsmanager:GetSecretValue",
        Resource: secretArn,
        Condition: {
          StringEquals: {
            "aws:PrincipalTag/tenant_id": tenantId,
          },
        },
      },
    ],
  };
}

export function buildPlatformResourcePolicy(
  platformRoleArns: string[],
  secretArn: string,
): ResourcePolicy {
  return {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "AllowPlatformRoles",
        Effect: "Allow",
        Principal: { AWS: platformRoleArns },
        Action: "secretsmanager:GetSecretValue",
        Resource: secretArn,
      },
      {
        Sid: "DenyTenantJITCredentials",
        Effect: "Deny",
        Principal: "*",
        Action: "secretsmanager:GetSecretValue",
        Resource: secretArn,
        Condition: {
          StringLike: {
            "aws:PrincipalTag/tenant_id": ["*"],
          },
        },
      },
    ],
  };
}

// ── Cross-tenant access check ────────────────────────────────────────

export function checkCrossTenantAccess(
  secretPath: string,
  callerTenantId: string,
): Result<void, AccessDeniedError> {
  // Extract tenant_id from path: /clearfin/{env}/{tenant_id}/...
  const segments = secretPath.split("/").filter(Boolean);
  // segments: ["clearfin", env, tenant_id, secret_type]
  if (segments.length < 3) {
    return ok(undefined);
  }
  const pathTenantId = segments[2];

  // Platform paths (_platform) are not subject to cross-tenant checks
  if (pathTenantId === "_platform") {
    return ok(undefined);
  }

  if (pathTenantId !== callerTenantId) {
    return err({
      code: "CROSS_TENANT_ACCESS_DENIED",
      pathTenantId,
      callerTenantId,
    });
  }

  return ok(undefined);
}

// ── Secrets Hierarchy Manager ────────────────────────────────────────

export class SecretsHierarchyManager {
  constructor(
    private readonly config: SecretsHierarchyConfig,
    private readonly client: SecretsManagerClient,
    private readonly logger: Logger,
  ) {}

  /**
   * Task 7.1: Provision tenant secret paths.
   * Creates /clearfin/{env}/{tenant_id}/bank-credentials, api-keys, config
   */
  async provisionTenant(tenantId: string, env: string): Promise<Result<void, ProvisionError>> {
    const paths = buildTenantSecretPaths(env, tenantId);

    for (const path of paths) {
      const secretType = path.split("/").pop()!;
      try {
        const output = await this.client.createSecret({
          Name: path,
          KmsKeyId: this.config.kmsKeyArn,
          Tags: [
            { Key: "tenant_id", Value: tenantId },
            { Key: "environment", Value: env },
            { Key: "secret_type", Value: secretType },
            { Key: "created_by", Value: "secrets-hierarchy-manager" },
          ],
        });

        // Apply tenant resource policy
        const policy = buildTenantResourcePolicy(tenantId, output.ARN);
        await this.client.putResourcePolicy({
          SecretId: output.ARN,
          ResourcePolicy: JSON.stringify(policy),
        });

        // Enable rotation
        await this.client.rotateSecret({
          SecretId: output.ARN,
          RotationRules: { AutomaticallyAfterDays: DEFAULT_ROTATION_DAYS },
        });

        this.logger.info("Tenant secret provisioned", { tenantId, env, path });
      } catch (error: unknown) {
        const reason = error instanceof Error ? error.message : "Unknown error";
        this.logger.error("Failed to provision tenant secret", { tenantId, env, path, reason });
        return err({ code: "PROVISION_FAILED", secretPath: path, reason });
      }
    }

    return ok(undefined);
  }

  /**
   * Task 7.3: Apply resource policy to a secret.
   */
  async applyResourcePolicy(
    secretArn: string,
    policyDocument: ResourcePolicy,
  ): Promise<Result<void, PolicyError>> {
    try {
      await this.client.putResourcePolicy({
        SecretId: secretArn,
        ResourcePolicy: JSON.stringify(policyDocument),
      });
      this.logger.info("Resource policy applied", { secretArn });
      return ok(undefined);
    } catch (error: unknown) {
      const reason = error instanceof Error ? error.message : "Unknown error";
      this.logger.error("Failed to apply resource policy", { secretArn, reason });
      return err({ code: "POLICY_APPLY_FAILED", secretArn, reason });
    }
  }

  /**
   * Task 7.5: Cross-tenant access denial.
   * Deny when path tenant_id differs from caller's session tenant_id; log CRITICAL.
   */
  validateAccess(secretPath: string, callerTenantId: string): Result<void, AccessDeniedError> {
    const result = checkCrossTenantAccess(secretPath, callerTenantId);
    if (!result.ok) {
      this.logger.critical("Cross-tenant access violation detected", {
        pathTenantId: result.error.pathTenantId,
        callerTenantId: result.error.callerTenantId,
        secretPath,
      });
    }
    return result;
  }

  /**
   * Task 7.7: Enable rotation with specified interval. AES-256 encryption via KMS.
   */
  async enableRotation(
    secretArn: string,
    intervalDays: number,
  ): Promise<Result<void, RotationError>> {
    try {
      await this.client.rotateSecret({
        SecretId: secretArn,
        RotationRules: { AutomaticallyAfterDays: intervalDays },
      });
      this.logger.info("Rotation enabled", { secretArn, intervalDays });
      return ok(undefined);
    } catch (error: unknown) {
      const reason = error instanceof Error ? error.message : "Unknown error";
      this.logger.error("Failed to enable rotation", { secretArn, intervalDays, reason });
      return err({ code: "ROTATION_CONFIG_FAILED", secretArn, intervalDays, reason });
    }
  }

  /**
   * Task 7.8: Tag a secret with tenant_id, environment, secret_type, created_by.
   */
  async tagSecret(
    secretArn: string,
    tags: SecretTags,
  ): Promise<Result<void, TagError>> {
    try {
      await this.client.tagResource({
        SecretId: secretArn,
        Tags: [
          { Key: "tenant_id", Value: tags.tenant_id },
          { Key: "environment", Value: tags.environment },
          { Key: "secret_type", Value: tags.secret_type },
          { Key: "created_by", Value: tags.created_by },
        ],
      });
      this.logger.info("Secret tagged", { secretArn, tags });
      return ok(undefined);
    } catch (error: unknown) {
      const reason = error instanceof Error ? error.message : "Unknown error";
      this.logger.error("Failed to tag secret", { secretArn, reason });
      return err({ code: "TAG_FAILED", secretArn, reason });
    }
  }

  /**
   * Task 7.10: Provision platform-level secrets.
   * Creates /clearfin/{env}/_platform/database-credentials, ai-api-keys, service-config
   * Applies resource policy restricting to platform roles and denying tenant JIT credentials.
   */
  async provisionPlatformSecrets(env: string): Promise<Result<void, ProvisionError>> {
    const paths = buildPlatformSecretPaths(env);

    for (const path of paths) {
      const secretType = path.split("/").pop()!;
      try {
        const output = await this.client.createSecret({
          Name: path,
          KmsKeyId: this.config.kmsKeyArn,
          Tags: [
            { Key: "tenant_id", Value: "_platform" },
            { Key: "environment", Value: env },
            { Key: "secret_type", Value: secretType },
            { Key: "created_by", Value: "secrets-hierarchy-manager" },
          ],
        });

        // Apply platform resource policy
        const policy = buildPlatformResourcePolicy(this.config.platformRoleArns, output.ARN);
        await this.client.putResourcePolicy({
          SecretId: output.ARN,
          ResourcePolicy: JSON.stringify(policy),
        });

        // Enable rotation (90-day interval)
        await this.client.rotateSecret({
          SecretId: output.ARN,
          RotationRules: { AutomaticallyAfterDays: DEFAULT_ROTATION_DAYS },
        });

        this.logger.info("Platform secret provisioned", { env, path });
      } catch (error: unknown) {
        const reason = error instanceof Error ? error.message : "Unknown error";
        this.logger.error("Failed to provision platform secret", { env, path, reason });
        return err({ code: "PROVISION_FAILED", secretPath: path, reason });
      }
    }

    return ok(undefined);
  }
}
