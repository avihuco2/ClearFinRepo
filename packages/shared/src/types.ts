// @clearfin/shared — Core domain types and interfaces

// ── Result utility type ──────────────────────────────────────────────

export type Result<T, E> =
  | { ok: true; value: T }
  | { ok: false; error: E };

export function ok<T>(value: T): Result<T, never> {
  return { ok: true, value };
}

export function err<E>(error: E): Result<never, E> {
  return { ok: false, error };
}

// ── User Record ──────────────────────────────────────────────────────

export interface UserRecord {
  id: string;
  googleSubjectId: string;
  email: string;
  name: string;
  tenantId: string;
  createdAt: Date;
  updatedAt: Date;
  lastLoginAt: Date;
}

// ── Session Token (JWT Payload) ──────────────────────────────────────

export interface SessionTokenPayload {
  sub: string;
  tenantId: string;
  iat: number;
  exp: number;
  jti: string;
  tokenFamily: string;
}

// ── Refresh Token Record ─────────────────────────────────────────────

export interface RefreshTokenRecord {
  id: string;
  tokenFamily: string;
  userId: string;
  tenantId: string;
  issuedAt: Date;
  expiresAt: Date;
  consumed: boolean;
  revokedAt: Date | null;
}

// ── JIT Credential ───────────────────────────────────────────────────

export interface JITCredential {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
  expiration: Date;
  tenantId: string;
  serviceName: string;
  roleSessionName: string;
}

// ── STS Session Policy ───────────────────────────────────────────────

export interface STSSessionPolicy {
  Version: "2012-10-17";
  Statement: Array<{
    Effect: "Allow" | "Deny";
    Action: string[];
    Resource: string;
  }>;
}

// ── Secret Metadata Tags ─────────────────────────────────────────────

export interface SecretTags {
  tenant_id: string;
  environment: string;
  secret_type: string;
  created_by: string;
}

// ── Sentinel Audit Record ────────────────────────────────────────────

export interface SentinelAuditRecord {
  id: string;
  artifactHash: string;
  decision: "approved" | "rejected";
  approverIdentity: string;
  reason: string | null;
  timestamp: Date;
  artifactContents: {
    iamPolicies: boolean;
    stsTrustPolicies: boolean;
    secretsManagerPolicies: boolean;
  };
}

// ── Rate Limit Entry ─────────────────────────────────────────────────

export interface RateLimitEntry {
  sourceIp: string;
  windowStart: Date;
  requestCount: number;
  consecutiveFailures: number;
  blockedUntil: Date | null;
}
