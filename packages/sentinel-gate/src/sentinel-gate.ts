// @clearfin/sentinel-gate — deployment approval checkpoint for CI/CD pipeline

import {
  type SentinelAuditRecord,
  type Result,
  ok,
  err,
} from "@clearfin/shared";
import { type Logger } from "@clearfin/shared";
import { createHash, randomUUID } from "node:crypto";

// ── Error types ──────────────────────────────────────────────────────

export type ArtifactValidationError = {
  code: "INCOMPLETE_ARTIFACT";
  missingComponents: string[];
};

export type ApprovalError =
  | { code: "ARTIFACT_VALIDATION_FAILED"; missingComponents: string[] }
  | { code: "APPROVAL_PENDING"; approvalId: string };

export type KillSwitchError = {
  code: "KILL_SWITCH_FAILED";
  deploymentId: string;
  reason: string;
};

// ── Deployment Artifact ──────────────────────────────────────────────

export interface DeploymentArtifact {
  iamPolicies?: unknown[];
  stsTrustPolicies?: unknown[];
  secretsManagerPolicies?: unknown[];
  [key: string]: unknown;
}

// ── CloudTrail Event ─────────────────────────────────────────────────

export interface CloudTrailEvent {
  eventName: string;
  eventSource: string;
  eventTime: string;
  requestParameters?: Record<string, unknown>;
  responseElements?: Record<string, unknown>;
  userIdentity?: Record<string, unknown>;
}

export interface SecurityAuditEvent {
  id: string;
  type: "IAM_POLICY_CHANGE" | "STS_TRUST_CHANGE" | "SECRETS_MANAGER_POLICY_CHANGE";
  sourceEvent: CloudTrailEvent;
  detectedAt: Date;
  severity: "CRITICAL";
}

// ── Dependency interfaces ────────────────────────────────────────────

export interface ApprovalService {
  requestApproval(approvalId: string, artifactHash: string): Promise<void>;
}

export interface IAMClient {
  revokePermissions(deploymentId: string): Promise<void>;
}

export interface CloudTrailClient {
  onEvent(callback: (event: CloudTrailEvent) => void): void;
}

export interface AuditLog {
  append(record: SentinelAuditRecord): void;
}

export interface NotificationService {
  notifyRejection(approvalId: string, reason: string): void;
}

// ── Monitored CloudTrail event sources and actions ───────────────────

const MONITORED_EVENTS: Record<string, SecurityAuditEvent["type"]> = {
  "iam.amazonaws.com:PutRolePolicy": "IAM_POLICY_CHANGE",
  "iam.amazonaws.com:AttachRolePolicy": "IAM_POLICY_CHANGE",
  "iam.amazonaws.com:DetachRolePolicy": "IAM_POLICY_CHANGE",
  "iam.amazonaws.com:DeleteRolePolicy": "IAM_POLICY_CHANGE",
  "iam.amazonaws.com:PutUserPolicy": "IAM_POLICY_CHANGE",
  "iam.amazonaws.com:AttachUserPolicy": "IAM_POLICY_CHANGE",
  "iam.amazonaws.com:CreatePolicyVersion": "IAM_POLICY_CHANGE",
  "sts.amazonaws.com:UpdateAssumeRolePolicy": "STS_TRUST_CHANGE",
  "iam.amazonaws.com:UpdateAssumeRolePolicy": "STS_TRUST_CHANGE",
  "secretsmanager.amazonaws.com:PutResourcePolicy": "SECRETS_MANAGER_POLICY_CHANGE",
  "secretsmanager.amazonaws.com:DeleteResourcePolicy": "SECRETS_MANAGER_POLICY_CHANGE",
};

// ── SentinelGate ─────────────────────────────────────────────────────

export class SentinelGate {
  private securityAuditEvents: SecurityAuditEvent[] = [];

  constructor(
    private readonly approvalService: ApprovalService,
    private readonly iamClient: IAMClient,
    private readonly cloudTrailClient: CloudTrailClient,
    private readonly auditLog: AuditLog,
    private readonly notificationService: NotificationService,
    private readonly logger: Logger,
  ) {}

  /**
   * Task 9.1: Validate deployment artifact contains all required policy documents.
   * Rejects incomplete artifacts with a list of missing components.
   * Requirement 5.2
   */
  validateArtifact(artifact: DeploymentArtifact): Result<void, ArtifactValidationError> {
    const missingComponents: string[] = [];

    if (!artifact.iamPolicies || !Array.isArray(artifact.iamPolicies) || artifact.iamPolicies.length === 0) {
      missingComponents.push("iamPolicies");
    }
    if (!artifact.stsTrustPolicies || !Array.isArray(artifact.stsTrustPolicies) || artifact.stsTrustPolicies.length === 0) {
      missingComponents.push("stsTrustPolicies");
    }
    if (!artifact.secretsManagerPolicies || !Array.isArray(artifact.secretsManagerPolicies) || artifact.secretsManagerPolicies.length === 0) {
      missingComponents.push("secretsManagerPolicies");
    }

    if (missingComponents.length > 0) {
      this.logger.warn("Incomplete deployment artifact", {
        artifactHash: this.computeArtifactHash(artifact),
        missingComponents,
      });
      return err({ code: "INCOMPLETE_ARTIFACT", missingComponents });
    }

    return ok(undefined);
  }

  /**
   * Task 9.3: Submit artifact for approval. Blocks promotion until
   * clearfin_sentinel provides explicit approval.
   * Requirement 5.1
   */
  async submitForApproval(artifact: DeploymentArtifact): Promise<Result<string, ApprovalError>> {
    // Validate artifact first
    const validation = this.validateArtifact(artifact);
    if (!validation.ok) {
      return err({
        code: "ARTIFACT_VALIDATION_FAILED",
        missingComponents: validation.error.missingComponents,
      });
    }

    const approvalId = randomUUID();
    const artifactHash = this.computeArtifactHash(artifact);

    this.logger.info("Submitting artifact for sentinel approval", {
      approvalId,
      artifactHash,
    });

    await this.approvalService.requestApproval(approvalId, artifactHash);

    return ok(approvalId);
  }

  /**
   * Task 9.4: Record approval/rejection decision with immutable audit trail.
   * On rejection: log reason, notify initiator, halt pipeline.
   * Requirements 5.3, 5.5
   */
  recordDecision(
    approvalId: string,
    decision: "approved" | "rejected",
    approverIdentity: string,
    artifact: DeploymentArtifact,
    reason: string | null = null,
  ): SentinelAuditRecord {
    const artifactHash = this.computeArtifactHash(artifact);

    const record: SentinelAuditRecord = {
      id: approvalId,
      artifactHash,
      decision,
      approverIdentity,
      reason: decision === "rejected" ? (reason ?? "No reason provided") : null,
      timestamp: new Date(),
      artifactContents: {
        iamPolicies: Array.isArray(artifact.iamPolicies) && artifact.iamPolicies.length > 0,
        stsTrustPolicies: Array.isArray(artifact.stsTrustPolicies) && artifact.stsTrustPolicies.length > 0,
        secretsManagerPolicies: Array.isArray(artifact.secretsManagerPolicies) && artifact.secretsManagerPolicies.length > 0,
      },
    };

    // Append to immutable audit log
    this.auditLog.append(record);

    if (decision === "rejected") {
      this.logger.warn("Deployment rejected by sentinel", {
        approvalId,
        artifactHash,
        approverIdentity,
        reason: record.reason,
      });
      this.notificationService.notifyRejection(approvalId, record.reason!);
    } else {
      this.logger.info("Deployment approved by sentinel", {
        approvalId,
        artifactHash,
        approverIdentity,
      });
    }

    return record;
  }

  /**
   * Task 9.6: Kill-switch — revoke IAM permissions and raise CRITICAL alert
   * on bypass detection.
   * Requirement 5.4
   */
  async triggerKillSwitch(deploymentId: string): Promise<Result<void, KillSwitchError>> {
    this.logger.critical("Kill-switch triggered — deployment bypass detected", {
      deploymentId,
    });

    try {
      await this.iamClient.revokePermissions(deploymentId);
      this.logger.alert("IAM permissions revoked for bypassed deployment", {
        deploymentId,
      });
      return ok(undefined);
    } catch (error: unknown) {
      const reason = error instanceof Error ? error.message : "UNKNOWN";
      this.logger.critical("Kill-switch failed to revoke permissions", {
        deploymentId,
        reason,
      });
      return err({ code: "KILL_SWITCH_FAILED", deploymentId, reason });
    }
  }

  /**
   * Task 9.7: Start CloudTrail event monitoring for IAM, STS trust,
   * and Secrets Manager policy modifications.
   * Generates security audit event within 60 seconds of detection.
   * Requirement 6.4
   */
  startCloudTrailMonitoring(): void {
    this.cloudTrailClient.onEvent((event) => {
      this.handleCloudTrailEvent(event);
    });
    this.logger.info("CloudTrail monitoring started for security-sensitive API calls");
  }

  handleCloudTrailEvent(event: CloudTrailEvent): SecurityAuditEvent | null {
    const key = `${event.eventSource}:${event.eventName}`;
    const eventType = MONITORED_EVENTS[key];

    if (!eventType) {
      return null;
    }

    const auditEvent: SecurityAuditEvent = {
      id: randomUUID(),
      type: eventType,
      sourceEvent: event,
      detectedAt: new Date(),
      severity: "CRITICAL",
    };

    this.securityAuditEvents.push(auditEvent);

    this.logger.alert("Security-sensitive API call detected", {
      eventType,
      eventName: event.eventName,
      eventSource: event.eventSource,
      eventTime: event.eventTime,
    });

    return auditEvent;
  }

  getSecurityAuditEvents(): SecurityAuditEvent[] {
    return [...this.securityAuditEvents];
  }

  /**
   * Compute SHA-256 hash of a deployment artifact.
   */
  computeArtifactHash(artifact: DeploymentArtifact): string {
    const content = JSON.stringify(artifact, Object.keys(artifact).sort());
    return createHash("sha256").update(content).digest("hex");
  }
}
