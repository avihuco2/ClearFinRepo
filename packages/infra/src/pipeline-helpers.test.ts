import { describe, it, expect } from 'vitest';
import {
  buildOidcTrustPolicy,
  extractArtifactSummary,
  getCacheControlHeader,
  formatDeploymentSummary,
  buildImageTag,
  isValidActionShaPin,
} from './pipeline-helpers.js';

// ── OIDC Trust Policy (Req 1.3) ─────────────────────────────────────

describe('buildOidcTrustPolicy', () => {
  const accountId = '123456789012';
  const org = 'clearfin';
  const repo = 'clearfin-secure-foundation';

  it('dev allows main and develop branches', () => {
    const policy = buildOidcTrustPolicy('dev', accountId, org, repo);
    const sub = policy.Statement[0].Condition.StringLike['token.actions.githubusercontent.com:sub'];
    expect(sub).toEqual([
      `repo:${org}/${repo}:ref:refs/heads/main`,
      `repo:${org}/${repo}:ref:refs/heads/develop`,
    ]);
  });

  it('staging allows main only', () => {
    const policy = buildOidcTrustPolicy('staging', accountId, org, repo);
    const sub = policy.Statement[0].Condition.StringLike['token.actions.githubusercontent.com:sub'];
    expect(sub).toBe(`repo:${org}/${repo}:ref:refs/heads/main`);
  });

  it('prod allows main only', () => {
    const policy = buildOidcTrustPolicy('prod', accountId, org, repo);
    const sub = policy.Statement[0].Condition.StringLike['token.actions.githubusercontent.com:sub'];
    expect(sub).toBe(`repo:${org}/${repo}:ref:refs/heads/main`);
  });

  it('sets correct OIDC provider ARN', () => {
    const policy = buildOidcTrustPolicy('prod', accountId, org, repo);
    expect(policy.Statement[0].Principal.Federated).toBe(
      `arn:aws:iam::${accountId}:oidc-provider/token.actions.githubusercontent.com`,
    );
  });

  it('sets audience to sts.amazonaws.com', () => {
    const policy = buildOidcTrustPolicy('prod', accountId, org, repo);
    expect(policy.Statement[0].Condition.StringEquals['token.actions.githubusercontent.com:aud']).toBe(
      'sts.amazonaws.com',
    );
  });

  it('uses AssumeRoleWithWebIdentity action', () => {
    const policy = buildOidcTrustPolicy('dev', accountId, org, repo);
    expect(policy.Statement[0].Action).toBe('sts:AssumeRoleWithWebIdentity');
  });

  it('throws for unknown environment', () => {
    expect(() => buildOidcTrustPolicy('unknown', accountId, org, repo)).toThrow(
      'Unknown environment: unknown',
    );
  });
});


// ── Artifact Summary Extraction (Req 5.3) ────────────────────────────

describe('extractArtifactSummary', () => {
  it('extracts IAM policies from templates', () => {
    const templates = [
      {
        Resources: {
          MyRole: { Type: 'AWS::IAM::Role', Properties: {} },
          MyPolicy: { Type: 'AWS::IAM::Policy', Properties: {} },
        },
      },
    ];
    const summary = extractArtifactSummary(templates);
    expect(summary.iamPolicies).toContain('MyRole');
    expect(summary.iamPolicies).toContain('MyPolicy');
  });

  it('extracts STS trust policies from IAM roles', () => {
    const templates = [
      {
        Resources: {
          DeployRole: { Type: 'AWS::IAM::Role', Properties: {} },
        },
      },
    ];
    const summary = extractArtifactSummary(templates);
    expect(summary.stsTrustPolicies).toContain('DeployRole');
  });

  it('extracts Secrets Manager policies', () => {
    const templates = [
      {
        Resources: {
          MySecret: { Type: 'AWS::SecretsManager::Secret', Properties: {} },
          MyResPolicy: { Type: 'AWS::SecretsManager::ResourcePolicy', Properties: {} },
        },
      },
    ];
    const summary = extractArtifactSummary(templates);
    expect(summary.secretsManagerPolicies).toContain('MySecret');
    expect(summary.secretsManagerPolicies).toContain('MyResPolicy');
  });

  it('reports missing IAM components', () => {
    const templates = [{ Resources: { Bucket: { Type: 'AWS::S3::Bucket', Properties: {} } } }];
    const summary = extractArtifactSummary(templates);
    expect(summary.missingComponents).toContain('iam-policy-documents');
    expect(summary.missingComponents).toContain('sts-trust-policies');
    expect(summary.missingComponents).toContain('secrets-manager-resource-policies');
  });

  it('reports no missing components when all types present', () => {
    const templates = [
      {
        Resources: {
          Role: { Type: 'AWS::IAM::Role', Properties: {} },
          Secret: { Type: 'AWS::SecretsManager::Secret', Properties: {} },
        },
      },
    ];
    const summary = extractArtifactSummary(templates);
    expect(summary.missingComponents).toEqual([]);
  });

  it('handles empty templates', () => {
    const summary = extractArtifactSummary([]);
    expect(summary.iamPolicies).toEqual([]);
    expect(summary.stsTrustPolicies).toEqual([]);
    expect(summary.secretsManagerPolicies).toEqual([]);
    expect(summary.missingComponents).toHaveLength(3);
  });

  it('handles templates with no Resources key', () => {
    const summary = extractArtifactSummary([{}]);
    expect(summary.missingComponents).toHaveLength(3);
  });
});


// ── Cache-Control Header Selection (Req 6.3) ────────────────────────

describe('getCacheControlHeader', () => {
  it('returns no-cache for index.html', () => {
    expect(getCacheControlHeader('index.html')).toBe('no-cache');
  });

  it('returns no-cache for nested path index.html', () => {
    expect(getCacheControlHeader('dist/index.html')).toBe('no-cache');
  });

  it('returns immutable max-age for hashed JS files', () => {
    expect(getCacheControlHeader('app.abc123.js')).toBe('max-age=31536000, immutable');
  });

  it('returns immutable max-age for hashed CSS files', () => {
    expect(getCacheControlHeader('styles.d4e5f6.css')).toBe('max-age=31536000, immutable');
  });

  it('returns immutable max-age for other asset files', () => {
    expect(getCacheControlHeader('logo.png')).toBe('max-age=31536000, immutable');
  });
});

// ── Deployment Summary Formatting (Req 9.4) ─────────────────────────

describe('formatDeploymentSummary', () => {
  const input = {
    gitCommitSha: 'abc1234def5678901234567890abcdef12345678',
    dockerImageTags: {
      'auth-service': 'abc1234',
      'sts-broker': 'abc1234',
    },
    cdkStacksDeployed: ['NetworkingStack', 'ComputeStack'],
    sentinelApprovalStatus: 'approved' as const,
    deploymentDuration: 320,
    environment: 'staging',
    timestamp: new Date('2025-01-15T10:30:00Z'),
  };

  it('includes git commit SHA', () => {
    const summary = formatDeploymentSummary(input);
    expect(summary).toContain(input.gitCommitSha);
  });

  it('includes all docker image tags', () => {
    const summary = formatDeploymentSummary(input);
    expect(summary).toContain('auth-service: abc1234');
    expect(summary).toContain('sts-broker: abc1234');
  });

  it('includes all CDK stack names', () => {
    const summary = formatDeploymentSummary(input);
    expect(summary).toContain('NetworkingStack');
    expect(summary).toContain('ComputeStack');
  });

  it('includes sentinel approval status', () => {
    const summary = formatDeploymentSummary(input);
    expect(summary).toContain('approved');
  });

  it('includes deployment duration', () => {
    const summary = formatDeploymentSummary(input);
    expect(summary).toContain('320');
  });

  it('includes environment name', () => {
    const summary = formatDeploymentSummary(input);
    expect(summary).toContain('staging');
  });
});


// ── Image Tag Construction (Req 7.5) ────────────────────────────────

describe('buildImageTag', () => {
  it('returns first 7 characters of a 40-char SHA', () => {
    expect(buildImageTag('abc1234def5678901234567890abcdef12345678')).toBe('abc1234');
  });

  it('produces a 7-character string', () => {
    const tag = buildImageTag('1234567890abcdef1234567890abcdef12345678');
    expect(tag).toHaveLength(7);
  });

  it('returns different tags for different SHAs', () => {
    const tag1 = buildImageTag('aaaaaaa000000000000000000000000000000000');
    const tag2 = buildImageTag('bbbbbbb000000000000000000000000000000000');
    expect(tag1).not.toBe(tag2);
  });
});

// ── Action SHA Pinning Validation (Req 9.1) ─────────────────────────

describe('isValidActionShaPin', () => {
  it('accepts a 40-char hex SHA pin', () => {
    expect(isValidActionShaPin('actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29')).toBe(true);
  });

  it('rejects a mutable tag like v4', () => {
    expect(isValidActionShaPin('actions/checkout@v4')).toBe(false);
  });

  it('rejects latest tag', () => {
    expect(isValidActionShaPin('actions/checkout@latest')).toBe(false);
  });

  it('rejects main branch reference', () => {
    expect(isValidActionShaPin('actions/checkout@main')).toBe(false);
  });

  it('rejects reference without @ separator', () => {
    expect(isValidActionShaPin('actions/checkout')).toBe(false);
  });

  it('rejects a short SHA (not 40 chars)', () => {
    expect(isValidActionShaPin('actions/checkout@abc1234')).toBe(false);
  });

  it('rejects uppercase hex characters', () => {
    expect(isValidActionShaPin('actions/checkout@A5AC7E51B41094C92402DA3B24376905380AFC29')).toBe(false);
  });
});
