// Unit tests for Sentinel_Gate
// Validates: Requirements 5.1-5.5, 6.4

import { describe, it, expect, vi } from "vitest";
import { SentinelGate } from "./sentinel-gate.js";
import type {
  DeploymentArtifact,
  ApprovalService,
  IAMClient,
  CloudTrailClient,
  AuditLog,
  NotificationService,
  CloudTrailEvent,
} from "./sentinel-gate.js";
import { createLogger } from "@clearfin/shared";

// ── Test helpers ─────────────────────────────────────────────────────

const noop = () => {};
const silentLogger = createLogger("sentinel-gate-test", "test-corr-id", {}, noop);

function makeGate(opts?: {
  approvalService?: ApprovalService;
  iamClient?: IAMClient;
  cloudTrailClient?: CloudTrailClient;
  auditLog?: AuditLog;
  notificationService?: NotificationService;
  logger?: ReturnType<typeof createLogger>;
}): SentinelGate {
  return new SentinelGate(
    opts?.approvalService ?? { requestApproval: async () => {} },
    opts?.iamClient ?? { revokePermissions: async () => {} },
    opts?.cloudTrailClient ?? { onEvent: () => {} },
    opts?.auditLog ?? { append: () => {} },
    opts?.notificationService ?? { notifyRejection: () => {} },
    opts?.logger ?? silentLogger,
  );
}

const completeArtifact: DeploymentArtifact = {
  iamPolicies: [{ Effect: "Allow", Action: ["sts:AssumeRole"] }],
  stsTrustPolicies: [{ Principal: { Service: "ecs-tasks.amazonaws.com" } }],
  secretsManagerPolicies: [{ Effect: "Allow", Resource: "*" }],
};

// ── 9.1: Artifact validation ─────────────────────────────────────────

describe("validateArtifact", () => {
  it("accepts a complete artifact with all three policy types", () => {
    const gate = makeGate();
    const result = gate.validateArtifact(completeArtifact);
    expect(result.ok).toBe(true);
  });

  it("rejects artifact missing iamPolicies", () => {
    const gate = makeGate();
    const artifact: DeploymentArtifact = {
      stsTrustPolicies: [{ trust: true }],
      secretsManagerPolicies: [{ policy: true }],
    };
    const result = gate.validateArtifact(artifact);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("INCOMPLETE_ARTIFACT");
      expect(result.error.missingComponents).toContain("iamPolicies");
    }
  });

  it("rejects artifact missing stsTrustPolicies", () => {
    const gate = makeGate();
    const artifact: DeploymentArtifact = {
      iamPolicies: [{ iam: true }],
      secretsManagerPolicies: [{ policy: true }],
    };
    const result = gate.validateArtifact(artifact);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.missingComponents).toContain("stsTrustPolicies");
    }
  });

  it("rejects artifact missing secretsManagerPolicies", () => {
    const gate = makeGate();
    const artifact: DeploymentArtifact = {
      iamPolicies: [{ iam: true }],
      stsTrustPolicies: [{ trust: true }],
    };
    const result = gate.validateArtifact(artifact);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.missingComponents).toContain("secretsManagerPolicies");
    }
  });

  it("rejects artifact with empty arrays", () => {
    const gate = makeGate();
    const artifact: DeploymentArtifact = {
      iamPolicies: [],
      stsTrustPolicies: [{ trust: true }],
      secretsManagerPolicies: [{ policy: true }],
    };
    const result = gate.validateArtifact(artifact);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.missingComponents).toContain("iamPolicies");
    }
  });

  it("lists all missing components when multiple are absent", () => {
    const gate = makeGate();
    const artifact: DeploymentArtifact = {};
    const result = gate.validateArtifact(artifact);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.missingComponents).toEqual([
        "iamPolicies",
        "stsTrustPolicies",
        "secretsManagerPolicies",
      ]);
    }
  });
});

// ── 9.3: Submit for approval ─────────────────────────────────────────

describe("submitForApproval", () => {
  it("returns an approvalId for a valid artifact", async () => {
    const requestApproval = vi.fn().mockResolvedValue(undefined);
    const gate = makeGate({ approvalService: { requestApproval } });

    const result = await gate.submitForApproval(completeArtifact);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(typeof result.value).toBe("string");
      expect(result.value.length).toBeGreaterThan(0);
    }
    expect(requestApproval).toHaveBeenCalledOnce();
  });

  it("rejects submission of an incomplete artifact without calling approval service", async () => {
    const requestApproval = vi.fn();
    const gate = makeGate({ approvalService: { requestApproval } });

    const result = await gate.submitForApproval({ iamPolicies: [{ a: 1 }] });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("ARTIFACT_VALIDATION_FAILED");
    }
    expect(requestApproval).not.toHaveBeenCalled();
  });

  it("passes the artifact hash to the approval service", async () => {
    const requestApproval = vi.fn().mockResolvedValue(undefined);
    const gate = makeGate({ approvalService: { requestApproval } });

    await gate.submitForApproval(completeArtifact);

    const [, artifactHash] = requestApproval.mock.calls[0];
    expect(artifactHash).toMatch(/^[a-f0-9]{64}$/);
  });
});

// ── 9.4: Record decision ─────────────────────────────────────────────

describe("recordDecision", () => {
  it("creates an audit record for approval", () => {
    const append = vi.fn();
    const gate = makeGate({ auditLog: { append } });

    const record = gate.recordDecision(
      "approval-001",
      "approved",
      "clearfin_sentinel",
      completeArtifact,
    );

    expect(record.id).toBe("approval-001");
    expect(record.decision).toBe("approved");
    expect(record.approverIdentity).toBe("clearfin_sentinel");
    expect(record.reason).toBeNull();
    expect(record.timestamp).toBeInstanceOf(Date);
    expect(record.artifactHash).toMatch(/^[a-f0-9]{64}$/);
    expect(record.artifactContents.iamPolicies).toBe(true);
    expect(record.artifactContents.stsTrustPolicies).toBe(true);
    expect(record.artifactContents.secretsManagerPolicies).toBe(true);
    expect(append).toHaveBeenCalledWith(record);
  });

  it("creates an audit record for rejection with reason", () => {
    const append = vi.fn();
    const notifyRejection = vi.fn();
    const gate = makeGate({
      auditLog: { append },
      notificationService: { notifyRejection },
    });

    const record = gate.recordDecision(
      "approval-002",
      "rejected",
      "clearfin_sentinel",
      completeArtifact,
      "IAM policy too permissive",
    );

    expect(record.decision).toBe("rejected");
    expect(record.reason).toBe("IAM policy too permissive");
    expect(append).toHaveBeenCalledWith(record);
    expect(notifyRejection).toHaveBeenCalledWith("approval-002", "IAM policy too permissive");
  });

  it("provides default reason when rejection has no reason", () => {
    const gate = makeGate();
    const record = gate.recordDecision(
      "approval-003",
      "rejected",
      "clearfin_sentinel",
      completeArtifact,
    );
    expect(record.reason).toBe("No reason provided");
  });

  it("logs rejection with WARN level", () => {
    const logs: string[] = [];
    const logger = createLogger("sentinel-gate-test", "corr-id", {}, (json) => logs.push(json));
    const gate = makeGate({ logger });

    gate.recordDecision("approval-004", "rejected", "sentinel", completeArtifact, "Bad policy");

    const warnLog = logs.find((l) => l.includes('"level":"WARN"'));
    expect(warnLog).toBeDefined();
    expect(warnLog).toContain("approval-004");
    expect(warnLog).toContain("Bad policy");
  });
});

// ── 9.6: Kill-switch ─────────────────────────────────────────────────

describe("triggerKillSwitch", () => {
  it("revokes IAM permissions and returns ok on success", async () => {
    const revokePermissions = vi.fn().mockResolvedValue(undefined);
    const gate = makeGate({ iamClient: { revokePermissions } });

    const result = await gate.triggerKillSwitch("deploy-001");
    expect(result.ok).toBe(true);
    expect(revokePermissions).toHaveBeenCalledWith("deploy-001");
  });

  it("returns KILL_SWITCH_FAILED on IAM revocation error", async () => {
    const revokePermissions = vi.fn().mockRejectedValue(new Error("AccessDenied"));
    const gate = makeGate({ iamClient: { revokePermissions } });

    const result = await gate.triggerKillSwitch("deploy-002");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.code).toBe("KILL_SWITCH_FAILED");
      expect(result.error.deploymentId).toBe("deploy-002");
      expect(result.error.reason).toBe("AccessDenied");
    }
  });

  it("logs CRITICAL alert on bypass detection", async () => {
    const logs: string[] = [];
    const logger = createLogger("sentinel-gate-test", "corr-id", {}, (json) => logs.push(json));
    const gate = makeGate({ logger });

    await gate.triggerKillSwitch("deploy-003");

    const criticalLog = logs.find((l) => l.includes('"level":"CRITICAL"'));
    expect(criticalLog).toBeDefined();
    expect(criticalLog).toContain("deploy-003");
  });
});

// ── 9.7: CloudTrail event monitoring ─────────────────────────────────

describe("CloudTrail event monitoring", () => {
  it("detects IAM policy modification events", () => {
    const gate = makeGate();
    const event: CloudTrailEvent = {
      eventName: "PutRolePolicy",
      eventSource: "iam.amazonaws.com",
      eventTime: new Date().toISOString(),
    };

    const auditEvent = gate.handleCloudTrailEvent(event);
    expect(auditEvent).not.toBeNull();
    expect(auditEvent!.type).toBe("IAM_POLICY_CHANGE");
    expect(auditEvent!.severity).toBe("CRITICAL");
    expect(auditEvent!.sourceEvent).toBe(event);
    expect(auditEvent!.detectedAt).toBeInstanceOf(Date);
  });

  it("detects STS trust relationship changes", () => {
    const gate = makeGate();
    const event: CloudTrailEvent = {
      eventName: "UpdateAssumeRolePolicy",
      eventSource: "iam.amazonaws.com",
      eventTime: new Date().toISOString(),
    };

    const auditEvent = gate.handleCloudTrailEvent(event);
    expect(auditEvent).not.toBeNull();
    expect(auditEvent!.type).toBe("STS_TRUST_CHANGE");
  });

  it("detects Secrets Manager resource policy changes", () => {
    const gate = makeGate();
    const event: CloudTrailEvent = {
      eventName: "PutResourcePolicy",
      eventSource: "secretsmanager.amazonaws.com",
      eventTime: new Date().toISOString(),
    };

    const auditEvent = gate.handleCloudTrailEvent(event);
    expect(auditEvent).not.toBeNull();
    expect(auditEvent!.type).toBe("SECRETS_MANAGER_POLICY_CHANGE");
  });

  it("ignores unrelated CloudTrail events", () => {
    const gate = makeGate();
    const event: CloudTrailEvent = {
      eventName: "DescribeInstances",
      eventSource: "ec2.amazonaws.com",
      eventTime: new Date().toISOString(),
    };

    const auditEvent = gate.handleCloudTrailEvent(event);
    expect(auditEvent).toBeNull();
  });

  it("accumulates security audit events", () => {
    const gate = makeGate();

    gate.handleCloudTrailEvent({
      eventName: "PutRolePolicy",
      eventSource: "iam.amazonaws.com",
      eventTime: new Date().toISOString(),
    });
    gate.handleCloudTrailEvent({
      eventName: "PutResourcePolicy",
      eventSource: "secretsmanager.amazonaws.com",
      eventTime: new Date().toISOString(),
    });

    const events = gate.getSecurityAuditEvents();
    expect(events).toHaveLength(2);
    expect(events[0].type).toBe("IAM_POLICY_CHANGE");
    expect(events[1].type).toBe("SECRETS_MANAGER_POLICY_CHANGE");
  });

  it("registers callback via startCloudTrailMonitoring", () => {
    const onEvent = vi.fn();
    const gate = makeGate({ cloudTrailClient: { onEvent } });

    gate.startCloudTrailMonitoring();
    expect(onEvent).toHaveBeenCalledOnce();
    expect(typeof onEvent.mock.calls[0][0]).toBe("function");
  });

  it("logs ALERT for detected security events", () => {
    const logs: string[] = [];
    const logger = createLogger("sentinel-gate-test", "corr-id", {}, (json) => logs.push(json));
    const gate = makeGate({ logger });

    gate.handleCloudTrailEvent({
      eventName: "AttachRolePolicy",
      eventSource: "iam.amazonaws.com",
      eventTime: new Date().toISOString(),
    });

    const alertLog = logs.find((l) => l.includes('"level":"ALERT"'));
    expect(alertLog).toBeDefined();
    expect(alertLog).toContain("AttachRolePolicy");
  });
});
