import { describe, it, expect } from 'vitest';
import { ClearFinOidcProvider } from './oidc-provider.js';

const DEFAULT_PROPS = {
  accountId: '123456789012',
  region: 'il-central-1',
  org: 'clearfin',
  repo: 'clearfin-secure-foundation',
  environments: ['dev', 'staging', 'prod'],
};

describe('ClearFinOidcProvider', () => {
  describe('providerConfig', () => {
    it('sets the GitHub OIDC issuer URL', () => {
      const provider = new ClearFinOidcProvider(DEFAULT_PROPS);
      expect(provider.providerConfig.issuerUrl).toBe(
        'https://token.actions.githubusercontent.com',
      );
    });

    it('sets audience to sts.amazonaws.com', () => {
      const provider = new ClearFinOidcProvider(DEFAULT_PROPS);
      expect(provider.providerConfig.audience).toBe('sts.amazonaws.com');
    });

    it('includes a thumbprint string', () => {
      const provider = new ClearFinOidcProvider(DEFAULT_PROPS);
      expect(provider.providerConfig.thumbprint).toBeTruthy();
    });
  });

  describe('roleConfigs', () => {
    it('creates one role per environment', () => {
      const provider = new ClearFinOidcProvider(DEFAULT_PROPS);
      expect(provider.roleConfigs).toHaveLength(3);
    });

    it('names roles as clearfin-{env}-github-actions-deploy', () => {
      const provider = new ClearFinOidcProvider(DEFAULT_PROPS);
      const names = provider.roleConfigs.map((r) => r.roleName);
      expect(names).toEqual([
        'clearfin-dev-github-actions-deploy',
        'clearfin-staging-github-actions-deploy',
        'clearfin-prod-github-actions-deploy',
      ]);
    });

    it('each role has a trust policy from buildOidcTrustPolicy', () => {
      const provider = new ClearFinOidcProvider(DEFAULT_PROPS);
      for (const role of provider.roleConfigs) {
        expect(role.trustPolicy.Version).toBe('2012-10-17');
        expect(role.trustPolicy.Statement).toHaveLength(1);
        expect(role.trustPolicy.Statement[0].Action).toBe(
          'sts:AssumeRoleWithWebIdentity',
        );
      }
    });

    it('dev trust policy allows main and develop branches', () => {
      const provider = new ClearFinOidcProvider(DEFAULT_PROPS);
      const dev = provider.roleConfigs.find((r) => r.environment === 'dev')!;
      const sub =
        dev.trustPolicy.Statement[0].Condition.StringLike[
          'token.actions.githubusercontent.com:sub'
        ];
      expect(sub).toContain(
        'repo:clearfin/clearfin-secure-foundation:ref:refs/heads/main',
      );
      expect(sub).toContain(
        'repo:clearfin/clearfin-secure-foundation:ref:refs/heads/develop',
      );
    });

    it('staging trust policy allows main only', () => {
      const provider = new ClearFinOidcProvider(DEFAULT_PROPS);
      const staging = provider.roleConfigs.find(
        (r) => r.environment === 'staging',
      )!;
      const sub =
        staging.trustPolicy.Statement[0].Condition.StringLike[
          'token.actions.githubusercontent.com:sub'
        ];
      expect(sub).toBe(
        'repo:clearfin/clearfin-secure-foundation:ref:refs/heads/main',
      );
    });

    it('attaches ECR push, CDK deploy, S3 sync, and CloudFront invalidation policies', () => {
      const provider = new ClearFinOidcProvider(DEFAULT_PROPS);
      for (const role of provider.roleConfigs) {
        const policyNames = role.inlinePolicies.map((p) => p.name);
        expect(policyNames).toEqual([
          'ecr-push',
          'cdk-deploy',
          's3-sync',
          'cloudfront-invalidation',
        ]);
      }
    });

    it('ECR policy scopes to the three service repositories', () => {
      const provider = new ClearFinOidcProvider(DEFAULT_PROPS);
      const role = provider.roleConfigs[0];
      const ecrPolicy = role.inlinePolicies.find((p) => p.name === 'ecr-push')!;
      const pushStatement = ecrPolicy.statements.find((s) =>
        s.Action.includes('ecr:PutImage'),
      )!;
      expect(pushStatement.Resource).toHaveLength(3);
      expect(pushStatement.Resource).toContain(
        'arn:aws:ecr:il-central-1:123456789012:repository/clearfin/auth-service',
      );
    });

    it('CDK deploy policy scopes cloudformation to clearfin-* stacks', () => {
      const provider = new ClearFinOidcProvider(DEFAULT_PROPS);
      const role = provider.roleConfigs[0];
      const cdkPolicy = role.inlinePolicies.find(
        (p) => p.name === 'cdk-deploy',
      )!;
      const cfnStatement = cdkPolicy.statements.find((s) =>
        s.Action.includes('cloudformation:*'),
      )!;
      expect(cfnStatement.Resource[0]).toContain('stack/clearfin-*');
    });

    it('S3 sync policy scopes to clearfin-{env}-login-page-assets bucket', () => {
      const provider = new ClearFinOidcProvider(DEFAULT_PROPS);
      const dev = provider.roleConfigs.find((r) => r.environment === 'dev')!;
      const s3Policy = dev.inlinePolicies.find((p) => p.name === 's3-sync')!;
      const putStatement = s3Policy.statements.find((s) =>
        s.Action.includes('s3:PutObject'),
      )!;
      expect(putStatement.Resource[0]).toBe(
        'arn:aws:s3:::clearfin-dev-login-page-assets/*',
      );
    });

    it('tags each role with Project, Environment, and Component', () => {
      const provider = new ClearFinOidcProvider(DEFAULT_PROPS);
      for (const role of provider.roleConfigs) {
        expect(role.tags.Project).toBe('ClearFin');
        expect(role.tags.Environment).toBe(role.environment);
        expect(role.tags.Component).toBe('oidc-deploy');
      }
    });
  });
});
