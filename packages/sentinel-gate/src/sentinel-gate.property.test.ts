// Property-based tests for Sentinel_Gate
// Uses fast-check for property testing, vitest as runner

import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { SentinelGate } from "./sentinel-gate.js";
import type {
  DeploymentArtifact,
  ApprovalService,
  IAMClient,
  CloudTrailClient,
  AuditLog,
  NotificationService,
} from "./sentinel-gate.js";
import { createLogger } from "@clearfin/shared";

// ── Helpers ──────────────────────────────────────────────────────────

const noop = () => {};
const silentLogger = createLogger("sentinel-gate-test", "test-corr-id", {}, noop);

function makeGate(): SentinelGate {
  const approvalService: ApprovalService = { requestApproval: async () => {} };
  const iamClient: IAMClient = { revokePermissions: async () => {} };
  const cloudTrailClient: CloudTrailClient = { onEvent: () => {} };
  const auditLog: AuditLog = { append: () => {} };
  const notificationService: NotificationService = { notifyRejection: () => {} };
  return new SentinelGate(
    approvalService,
    iamClient,
    cloudTrailClient,
    auditLog,
    notificationService,
    silentLogger,
  );
}

// Generators
const nonEmptyArray = fc.array(fc.anything(), { minLength: 1, maxLength: 5 });
const emptyOrMissing = fc.constantFrom(undefined, null, []);

// ── Property 17: Deployment Artifact Validation ──────────────────────
// **Validates: Requirements 5.2**

describe("Property 17: Deployment Artifact Validation", () => {
  it("accepts artifacts containing all three required policy types", () => {
    fc.assert(
      fc.property(nonEmptyArray, nonEmptyArray, nonEmptyArray, (iam, sts, sm) => {
        const gate = makeGate();
        const artifact: DeploymentArtifact = {
          iamPolicies: iam,
          stsTrustPolicies: sts,
          secretsManagerPolicies: sm,
        };
        const result = gate.validateArtifact(artifact);
        expect(result.ok).toBe(true);
      }),
      { numRuns: 100 },
    );
  });

  it("rejects artifacts missing any combination of required components", () => {
    // Generate a bitmask 1-6 (at least one missing, not all present = 7)
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 6 }),
        nonEmptyArray,
        nonEmptyArray,
        nonEmptyArray,
        (mask, iam, sts, sm) => {
          const gate = makeGate();
          const artifact: DeploymentArtifact = {
            iamPolicies: mask & 1 ? iam : undefined,
            stsTrustPolicies: mask & 2 ? sts : undefined,
            secretsManagerPolicies: mask & 4 ? sm : undefined,
          };

          // At least one component is missing (mask < 7)
          const expectedMissing: string[] = [];
          if (!(mask & 1)) expectedMissing.push("iamPolicies");
          if (!(mask & 2)) expectedMissing.push("stsTrustPolicies");
          if (!(mask & 4)) expectedMissing.push("secretsManagerPolicies");

          if (expectedMissing.length > 0) {
            const result = gate.validateArtifact(artifact);
            expect(result.ok).toBe(false);
            if (!result.ok) {
              expect(result.error.code).toBe("INCOMPLETE_ARTIFACT");
              expect(result.error.missingComponents).toEqual(expectedMissing);
            }
          }
        },
      ),
      { numRuns: 100 },
    );
  });

  it("rejects artifacts with empty arrays for any required component", () => {
    fc.assert(
      fc.property(nonEmptyArray, nonEmptyArray, (iam, sts) => {
        const gate = makeGate();
        const artifact: DeploymentArtifact = {
          iamPolicies: iam,
          stsTrustPolicies: sts,
          secretsManagerPolicies: [],
        };
        const result = gate.validateArtifact(artifact);
        expect(result.ok).toBe(false);
        if (!result.ok) {
          expect(result.error.missingComponents).toContain("secretsManagerPolicies");
        }
      }),
      { numRuns: 100 },
    );
  });
});

// ── Property 18: Audit Record Construction ───────────────────────────
// **Validates: Requirements 5.5**

describe("Property 18: Audit Record Construction", () => {
  it("produces audit records with timestamp, SHA-256 artifact hash, and approver identity for any decision", () => {
    const decisionArb = fc.constantFrom("approved" as const, "rejected" as const);
    const approverArb = fc.stringMatching(/^[a-zA-Z0-9_@.-]{1,64}$/);
    const reasonArb = fc.option(fc.string({ minLength: 1, maxLength: 200 }), { nil: null });

    fc.assert(
      fc.property(decisionArb, approverArb, reasonArb, (decision, approver, reason) => {
        const gate = makeGate();
        const artifact: DeploymentArtifact = {
          iamPolicies: [{ effect: "Allow" }],
          stsTrustPolicies: [{ trust: true }],
          secretsManagerPolicies: [{ resource: "*" }],
        };

        const record = gate.recordDecision("approval-123", decision, approver, artifact, reason);

        // Timestamp must be present and a valid Date
        expect(record.timestamp).toBeInstanceOf(Date);

        // Artifact hash must be a 64-char hex string (SHA-256)
        expect(record.artifactHash).toMatch(/^[a-f0-9]{64}$/);

        // Approver identity must match input
        expect(record.approverIdentity).toBe(approver);

        // Decision must match input
        expect(record.decision).toBe(decision);

        // ID must be present
        expect(record.id).toBe("approval-123");

        // For approvals, reason is null; for rejections, reason is non-null
        if (decision === "approved") {
          expect(record.reason).toBeNull();
        } else {
          expect(record.reason).not.toBeNull();
          expect(typeof record.reason).toBe("string");
        }

        // artifactContents must reflect the artifact
        expect(record.artifactContents.iamPolicies).toBe(true);
        expect(record.artifactContents.stsTrustPolicies).toBe(true);
        expect(record.artifactContents.secretsManagerPolicies).toBe(true);
      }),
      { numRuns: 100 },
    );
  });

  it("artifact hash is deterministic for the same artifact", () => {
    fc.assert(
      fc.property(
        fc.json(),
        (jsonStr) => {
          const gate = makeGate();
          const artifact: DeploymentArtifact = {
            iamPolicies: [jsonStr],
            stsTrustPolicies: [{ a: 1 }],
            secretsManagerPolicies: [{ b: 2 }],
          };

          const hash1 = gate.computeArtifactHash(artifact);
          const hash2 = gate.computeArtifactHash(artifact);
          expect(hash1).toBe(hash2);
        },
      ),
      { numRuns: 100 },
    );
  });
});
