// @clearfin/infra — OIDC provider and per-environment deploy role configurations
// Validates: Requirements 1.1, 1.2, 1.3, 1.4

import { buildOidcTrustPolicy } from '../pipeline-helpers.js';
import type { OidcTrustPolicy } from '../pipeline-helpers.js';

// ── Interfaces ───────────────────────────────────────────────────────

export interface OidcProviderConfig {
  issuerUrl: 'https://token.actions.githubusercontent.com';
  audience: 'sts.amazonaws.com';
  thumbprint: string;
}

export interface PolicyStatement {
  Effect: 'Allow';
  Action: string[];
  Resource: string[];
}

export interface OidcRoleConfig {
  roleName: string;
  environment: string;
  trustPolicy: OidcTrustPolicy;
  inlinePolicies: Array<{
    name: string;
    statements: PolicyStatement[];
  }>;
  tags: Record<string, string>;
}

export interface ClearFinOidcProviderProps {
  accountId: string;
  region: string;
  org: string;
  repo: string;
  environments: string[];
}

// ── OIDC Provider Construct ──────────────────────────────────────────

/**
 * Produces configuration objects for the GitHub Actions OIDC provider
 * and per-environment IAM deploy roles with scoped permissions.
 *
 * Each role's trust policy is branch-scoped via buildOidcTrustPolicy(),
 * and permissions follow least-privilege for ECR push, CDK deploy,
 * S3 sync, and CloudFront invalidation.
 */
export class ClearFinOidcProvider {
  public readonly providerConfig: OidcProviderConfig;
  public readonly roleConfigs: OidcRoleConfig[];

  constructor(props: ClearFinOidcProviderProps) {
    const { accountId, region, org, repo, environments } = props;

    // GitHub OIDC provider thumbprint (well-known, used by AWS)
    this.providerConfig = {
      issuerUrl: 'https://token.actions.githubusercontent.com',
      audience: 'sts.amazonaws.com',
      thumbprint: '6938fd4d98bab03faadb97b34396831e3780aea1',
    };

    this.roleConfigs = environments.map((env) =>
      buildRoleConfig(env, accountId, region, org, repo),
    );
  }
}

// ── Role builder (private) ───────────────────────────────────────────

function buildRoleConfig(
  env: string,
  accountId: string,
  region: string,
  org: string,
  repo: string,
): OidcRoleConfig {
  return {
    roleName: `clearfin-${env}-github-actions-deploy`,
    environment: env,
    trustPolicy: buildOidcTrustPolicy(env, accountId, org, repo),
    inlinePolicies: [
      buildEcrPolicy(accountId, region),
      buildCdkDeployPolicy(accountId, region),
      buildS3SyncPolicy(env),
      buildCloudFrontInvalidationPolicy(),
    ],
    tags: {
      Project: 'ClearFin',
      Environment: env,
      Component: 'oidc-deploy',
    },
  };
}

// ── Scoped permission policies ───────────────────────────────────────

/** ECR push permissions for all three service repositories. */
function buildEcrPolicy(accountId: string, region: string): {
  name: string;
  statements: PolicyStatement[];
} {
  const services = ['auth-service', 'sts-broker', 'secrets-hierarchy-manager'];
  return {
    name: 'ecr-push',
    statements: [
      {
        Effect: 'Allow',
        Action: ['ecr:GetAuthorizationToken'],
        Resource: ['*'],
      },
      {
        Effect: 'Allow',
        Action: [
          'ecr:BatchCheckLayerAvailability',
          'ecr:PutImage',
          'ecr:InitiateLayerUpload',
          'ecr:UploadLayerPart',
          'ecr:CompleteLayerUpload',
          'ecr:DescribeImageScanFindings',
        ],
        Resource: services.map(
          (svc) => `arn:aws:ecr:${region}:${accountId}:repository/clearfin/${svc}`,
        ),
      },
    ],
  };
}

/** CDK deploy permissions scoped to clearfin-* stacks + CDK execution roles. */
function buildCdkDeployPolicy(accountId: string, region: string): {
  name: string;
  statements: PolicyStatement[];
} {
  return {
    name: 'cdk-deploy',
    statements: [
      {
        Effect: 'Allow',
        Action: ['cloudformation:*'],
        Resource: [
          `arn:aws:cloudformation:${region}:${accountId}:stack/clearfin-*/*`,
        ],
      },
      {
        Effect: 'Allow',
        Action: ['sts:AssumeRole'],
        Resource: [
          `arn:aws:iam::${accountId}:role/cdk-*`,
        ],
      },
      {
        Effect: 'Allow',
        Action: ['ssm:GetParameter'],
        Resource: [
          `arn:aws:ssm:${region}:${accountId}:parameter/cdk-bootstrap/*`,
        ],
      },
    ],
  };
}

/** S3 sync permissions scoped to the login page bucket for the environment. */
function buildS3SyncPolicy(env: string): {
  name: string;
  statements: PolicyStatement[];
} {
  const bucket = `clearfin-${env}-login-page`;
  return {
    name: 's3-sync',
    statements: [
      {
        Effect: 'Allow',
        Action: ['s3:PutObject', 's3:DeleteObject'],
        Resource: [`arn:aws:s3:::${bucket}/*`],
      },
      {
        Effect: 'Allow',
        Action: ['s3:ListBucket'],
        Resource: [`arn:aws:s3:::${bucket}`],
      },
    ],
  };
}

/** CloudFront invalidation permission (scoped to all distributions in account). */
function buildCloudFrontInvalidationPolicy(): {
  name: string;
  statements: PolicyStatement[];
} {
  return {
    name: 'cloudfront-invalidation',
    statements: [
      {
        Effect: 'Allow',
        Action: ['cloudfront:CreateInvalidation'],
        Resource: ['*'],
      },
    ],
  };
}
