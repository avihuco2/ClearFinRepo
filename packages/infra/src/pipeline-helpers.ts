// @clearfin/infra — GitHub Actions pipeline helper functions
// Validates: Requirements 1.3, 5.3, 6.3, 9.1, 9.4

// ── Interfaces ───────────────────────────────────────────────────────

export interface OidcTrustPolicy {
  Version: '2012-10-17';
  Statement: Array<{
    Effect: 'Allow';
    Principal: { Federated: string };
    Action: 'sts:AssumeRoleWithWebIdentity';
    Condition: {
      StringEquals: { 'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com' };
      StringLike: { 'token.actions.githubusercontent.com:sub': string | string[] };
    };
  }>;
}

export interface ArtifactSummary {
  iamPolicies: string[];
  stsTrustPolicies: string[];
  secretsManagerPolicies: string[];
  missingComponents: string[];
}

export interface DeploymentSummaryInput {
  gitCommitSha: string;
  dockerImageTags: Record<string, string>;
  cdkStacksDeployed: string[];
  sentinelApprovalStatus: 'approved' | 'not-required' | 'rejected' | 'timeout';
  deploymentDuration: number;
  environment: string;
  timestamp: Date;
}

// ── Branch restrictions per environment ──────────────────────────────

const BRANCH_RESTRICTIONS: Record<string, string[]> = {
  dev: ['main', 'develop'],
  staging: ['main'],
  prod: ['main'],
};

// ── OIDC Trust Policy (Req 1.3) ─────────────────────────────────────

export function buildOidcTrustPolicy(
  env: string,
  accountId: string,
  org: string,
  repo: string,
): OidcTrustPolicy {
  const branches = BRANCH_RESTRICTIONS[env];
  if (!branches) {
    throw new Error(`Unknown environment: ${env}. Expected one of: dev, staging, prod`);
  }

  const subConditions = branches.map(
    (branch) => `repo:${org}/${repo}:ref:refs/heads/${branch}`,
  );

  return {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Principal: {
          Federated: `arn:aws:iam::${accountId}:oidc-provider/token.actions.githubusercontent.com`,
        },
        Action: 'sts:AssumeRoleWithWebIdentity',
        Condition: {
          StringEquals: {
            'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com',
          },
          StringLike: {
            'token.actions.githubusercontent.com:sub':
              subConditions.length === 1 ? subConditions[0] : subConditions,
          },
        },
      },
    ],
  };
}

// ── Artifact Summary Extraction (Req 5.3) ────────────────────────────

interface CfnResource {
  Type: string;
  Properties?: Record<string, unknown>;
}

interface CfnTemplate {
  Resources?: Record<string, CfnResource>;
}

export function extractArtifactSummary(cfnTemplates: CfnTemplate[]): ArtifactSummary {
  const iamPolicies: string[] = [];
  const stsTrustPolicies: string[] = [];
  const secretsManagerPolicies: string[] = [];

  for (const template of cfnTemplates) {
    const resources = template.Resources ?? {};
    for (const [logicalId, resource] of Object.entries(resources)) {
      const type = resource.Type;
      if (
        type === 'AWS::IAM::Policy' ||
        type === 'AWS::IAM::ManagedPolicy' ||
        type === 'AWS::IAM::Role'
      ) {
        iamPolicies.push(logicalId);
      }
      if (type === 'AWS::IAM::Role' || type === 'AWS::STS::AssumeRole') {
        stsTrustPolicies.push(logicalId);
      }
      if (
        type === 'AWS::SecretsManager::Secret' ||
        type === 'AWS::SecretsManager::ResourcePolicy'
      ) {
        secretsManagerPolicies.push(logicalId);
      }
    }
  }

  const missingComponents: string[] = [];
  if (iamPolicies.length === 0) missingComponents.push('iam-policy-documents');
  if (stsTrustPolicies.length === 0) missingComponents.push('sts-trust-policies');
  if (secretsManagerPolicies.length === 0) missingComponents.push('secrets-manager-resource-policies');

  return { iamPolicies, stsTrustPolicies, secretsManagerPolicies, missingComponents };
}

// ── Cache-Control Header Selection (Req 6.3) ────────────────────────

export function getCacheControlHeader(filename: string): string {
  const basename = filename.split('/').pop() ?? filename;
  if (basename === 'index.html') {
    return 'no-cache';
  }
  return 'max-age=31536000, immutable';
}

// ── Deployment Summary Formatting (Req 9.4) ─────────────────────────

export function formatDeploymentSummary(input: DeploymentSummaryInput): string {
  const imageTagLines = Object.entries(input.dockerImageTags)
    .map(([service, tag]) => `  ${service}: ${tag}`)
    .join('\n');

  const stackLines = input.cdkStacksDeployed.join(', ');

  return [
    `## Deployment Summary`,
    ``,
    `**Environment:** ${input.environment}`,
    `**Git SHA:** ${input.gitCommitSha}`,
    `**Timestamp:** ${input.timestamp.toISOString()}`,
    `**Duration:** ${input.deploymentDuration}s`,
    `**Sentinel Status:** ${input.sentinelApprovalStatus}`,
    ``,
    `### Docker Image Tags`,
    imageTagLines,
    ``,
    `### CDK Stacks Deployed`,
    stackLines,
  ].join('\n');
}

// ── Image Tag Construction (Req 7.5) ────────────────────────────────

export function buildImageTag(gitSha: string): string {
  return gitSha.slice(0, 7);
}

// ── Action SHA Pinning Validation (Req 9.1) ─────────────────────────

const SHA_PIN_REGEX = /^[0-9a-f]{40}$/;

export function isValidActionShaPin(usesRef: string): boolean {
  const atIndex = usesRef.lastIndexOf('@');
  if (atIndex === -1) return false;
  const version = usesRef.slice(atIndex + 1);
  return SHA_PIN_REGEX.test(version);
}
