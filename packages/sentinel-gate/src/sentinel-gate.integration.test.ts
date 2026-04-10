// Integration test: Sentinel Gate deployment approval flow
// Tests: artifact validation → submit for approval → record decision → promote or halt
// Also tests kill-switch integration for bypass detection.
// Requirements: 5.1–5.5

import { describe, it, expect, beforeEach } from "vitest";
import { createLogger } from "@clearfin/shared";
import type { SentinelAuditRecord } from "@clearfin/shared";
import {
  SentinelGate,
  type DeploymentArtifact,
  type ApprovalService,
  type IAMClient,
  type CloudTrailClient,
  type AuditLog,
  type NotificationService,
} from "./sentinel-gate.js";

// ── Mock factories ───────────────────────────────────────────────────

function createMockApprovalService(): ApprovalService & { requests: Array<{ approvalId: string; artifactHash: string }> } {
  const requests: Array<{ approvalId: string; artifactHash: string }> = [];
  return {
    requests,
    async requestApproval(approvalId, artifactHash) {
      requests.push({ approvalId, artifactHash });
    },
  };
}

function createMockIAMClient(): IAMClient & { revoked: string[] } {
  const revoked: string[] = [];
  return {
    revoked,
    async revokePermissions(deploymentId) {
      revoked.push(deploymentId);
    },
  };
}

function createFailingIAMClient(): IAMClient {
  return {
    async revokePermissions() {
      throw new Error("IAM revocation failed");
    },
  };
}

function createMockCloudTrailClient(): CloudTrailClient & { trigger: (event: any) => void } {
  let callback: ((event: any) => void) | null = null;
  return {
    onEvent(cb) { callback = cb; },
    trigger(event) { if (callback) callback(event); },
  };
}

function createMockAuditLog(): AuditLog & { records: SentinelAuditRecord[] } {
  const records: SentinelAuditRecord[] = [];
  return {
    records,
    append(record) { records.push(record); },
  };
}

function createMockNotificationService(): NotificationService & { rejections: Array<{ approvalId: string; reason: string }> } {
  const rejections: Array<{ approvalId: string; reason: string }> = [];
  return {
    rejections,
    notifyRejection(approvalId, reason) { rejections.push({ approvalId, reason }); },
  };
}

const VALID_ARTIFACT: DeploymentArtifact = {
  iamPolicies: [{ Effect: "Allow", Action: ["sts:AssumeRole"], Resource: "*" }],
  stsTrustPolicies: [{ Effect: "Allow", Principal: { Service: "ecs-tasks.amazonaws.com" } }],
  secretsManagerPolicies: [{ Effect: "Allow", Action: ["secretsmanager:GetSecretValue"] }],
};

const INCOMPLETE_ARTIFACT: DeploymentArtifact = {
  iamPolicies: [{ Effect: "Allow" }],
  // Missing stsTrustPolicies and secretsManagerPolicies
};

function makeGate(opts?: { iamClient?: IAMClient }) {
  const logger = createLogger("sentinel-integration", "test-corr", {}, () => {});
  const approvalService = createMockApprovalService();
  const iamClient = opts?.iamClient ?? createMockIAMClient();
  const cloudTrailClient = createMockCloudTrailClient();
  const auditLog = createMockAuditLog();
  const notificationService = createMockNotificationService();

  const gate = new SentinelGate(
    approvalService,
    iamClient,
    cloudTrailClient,
    auditLog,
    notificationService,
    logger,
  );

  return { gate, approvalService, iamClient, cloudTrailClient, auditLog, notificationService };
}

// ── Integration Tests ────────────────────────────────────────────────

describe("Sentinel Gate Integration: full deployment approval flow", () => {
  it("validates artifact → submits for approval → records approval decision", async () => {
    const { gate, approvalService, auditLog } = makeGate();

    // Step 1: Submit for approval (includes validation)
    const submitResult = await gate.submitForApproval(VALID_ARTIFACT);
    expect(submitResult.ok).toBe(true);
    if (!submitResult.ok) return;

    const approvalId = submitResult.value;
    expect(approvalService.requests).toHaveLength(1);
    expect(approvalService.requests[0].approvalId).toBe(approvalId);

    // Step 2: Record approval decision
    const record = gate.recordDecision(
      approvalId,
      "approved",
      "clearfin_sentinel",
      VALID_ARTIFACT,
    );

    expect(record.decision).toBe("approved");
    expect(record.approverIdentity).toBe("clearfin_sentinel");
    expect(record.artifactHash).toBeTruthy();
    expect(record.reason).toBeNull();
    expect(record.timestamp).toBeInstanceOf(Date);
    expect(record.artifactContents.iamPolicies).toBe(true);
    expect(record.artifactContents.stsTrustPolicies).toBe(true);
    expect(record.artifactContents.secretsManagerPolicies).toBe(true);

    // Verify audit log
    expect(auditLog.records).toHaveLength(1);
    expect(auditLog.records[0].id).toBe(approvalId);
  });

  it("rejects incomplete artifact before approval submission", async () => {
    const { gate, approvalService } = makeGate();

    const result = await gate.submitForApproval(INCOMPLETE_ARTIFACT);
    expect(result.ok).toBe(false);
    if (result.ok) return;

    expect(result.error.code).toBe("ARTIFACT_VALIDATION_FAILED");
    expect(result.error.missingComponents).toContain("stsTrustPolicies");
    expect(result.error.missingComponents).toContain("secretsManagerPolicies");

    // No approval request should have been made
    expect(approvalService.requests).toHaveLength(0);
  });

  it("records rejection with reason and notifies initiator", async () => {
    const { gate, auditLog, notificationService } = makeGate();

    const submitResult = await gate.submitForApproval(VALID_ARTIFACT);
    expect(submitResult.ok).toBe(true);
    if (!submitResult.ok) return;

    const approvalId = submitResult.value;

    const record = gate.recordDecision(
      approvalId,
      "rejected",
      "clearfin_sentinel",
      VALID_ARTIFACT,
      "IAM policy too permissive",
    );

    expect(record.decision).toBe("rejected");
    expect(record.reason).toBe("IAM policy too permissive");

    // Verify notification was sent
    expect(notificationService.rejections).toHaveLength(1);
    expect(notificationService.rejections[0].approvalId).toBe(approvalId);
    expect(notificationService.rejections[0].reason).toBe("IAM policy too permissive");

    // Verify audit log
    expect(auditLog.records).toHaveLength(1);
  });

  it("triggers kill-switch on bypass detection and revokes IAM permissions", async () => {
    const mocks = makeGate();
    const { gate } = mocks;
    const iamClient = mocks.iamClient as IAMClient & { revoked: string[] };

    const result = await gate.triggerKillSwitch("deploy-bypass-001");
    expect(result.ok).toBe(true);
    expect(iamClient.revoked).toContain("deploy-bypass-001");
  });

  it("returns error when kill-switch IAM revocation fails", async () => {
    const { gate } = makeGate({ iamClient: createFailingIAMClient() });

    const result = await gate.triggerKillSwitch("deploy-bypass-002");
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.code).toBe("KILL_SWITCH_FAILED");
    expect(result.error.deploymentId).toBe("deploy-bypass-002");
  });

  it("detects security-sensitive CloudTrail events", () => {
    const { gate, cloudTrailClient } = makeGate();
    gate.startCloudTrailMonitoring();

    // Simulate IAM policy modification event
    (cloudTrailClient as any).trigger({
      eventName: "PutRolePolicy",
      eventSource: "iam.amazonaws.com",
      eventTime: new Date().toISOString(),
      requestParameters: { roleName: "clearfin-base-role" },
    });

    const events = gate.getSecurityAuditEvents();
    expect(events).toHaveLength(1);
    expect(events[0].type).toBe("IAM_POLICY_CHANGE");
    expect(events[0].severity).toBe("CRITICAL");
  });

  it("detects Secrets Manager policy changes via CloudTrail", () => {
    const { gate, cloudTrailClient } = makeGate();
    gate.startCloudTrailMonitoring();

    (cloudTrailClient as any).trigger({
      eventName: "PutResourcePolicy",
      eventSource: "secretsmanager.amazonaws.com",
      eventTime: new Date().toISOString(),
    });

    const events = gate.getSecurityAuditEvents();
    expect(events).toHaveLength(1);
    expect(events[0].type).toBe("SECRETS_MANAGER_POLICY_CHANGE");
  });
});
