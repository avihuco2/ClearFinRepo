// @clearfin/infra — CDK stack snapshot tests
// Validates: Requirements 8.2, 8.3

import { describe, it, expect } from 'vitest';
import {
  ClearFinNetworkingStack,
  ClearFinComputeStack,
  ClearFinSecurityStack,
  ClearFinStaticHostingStack,
} from './stacks.js';
import type { CdkStackContext } from './stacks.js';

const testContext: CdkStackContext = {
  environment: 'prod',
  accountId: '123456789012',
  region: 'il-central-1',
  imageTag: 'abc1234',
  domainName: 'clearfin.example.com',
  certificateArn: 'arn:aws:acm:il-central-1:123456789012:certificate/test-cert',
};

// ── NetworkingStack ─────────────────────────────────────────────────

describe('ClearFinNetworkingStack', () => {
  const stack = new ClearFinNetworkingStack(testContext);

  it('snapshot: full synthesized configuration', () => {
    expect({
      stackName: stack.stackName,
      tags: stack.tags,
      vpcConfig: stack.vpcConfig,
    }).toMatchSnapshot();
  });

  it('tags include Project, Environment, and Component', () => {
    expect(stack.tags).toEqual({
      Project: 'ClearFin',
      Environment: 'prod',
      Component: 'networking',
    });
  });

  it('vpcConfig has VPC endpoints for all required services', () => {
    const services = stack.vpcConfig.vpcEndpoints.map((e) => e.service);
    expect(services).toContain('com.amazonaws.il-central-1.ecr.api');
    expect(services).toContain('com.amazonaws.il-central-1.ecr.dkr');
    expect(services).toContain('com.amazonaws.il-central-1.sts');
    expect(services).toContain('com.amazonaws.il-central-1.secretsmanager');
    expect(services).toContain('com.amazonaws.il-central-1.kms');
    expect(services).toContain('com.amazonaws.il-central-1.logs');
    expect(services).toContain('com.amazonaws.il-central-1.monitoring');
    expect(services).toContain('com.amazonaws.il-central-1.s3');
  });
});

// ── ComputeStack ────────────────────────────────────────────────────

describe('ClearFinComputeStack', () => {
  const networkingStack = new ClearFinNetworkingStack(testContext);
  const securityStack = new ClearFinSecurityStack(testContext);
  const stack = new ClearFinComputeStack(testContext, networkingStack, securityStack);

  it('snapshot: full synthesized configuration', () => {
    expect({
      stackName: stack.stackName,
      tags: stack.tags,
      ecsClusterConfig: stack.ecsClusterConfig,
      ecrRepositoryConfigs: stack.ecrRepositoryConfigs,
      albConfig: stack.albConfig,
    }).toMatchSnapshot();
  });

  it('tags include Project, Environment, and Component', () => {
    expect(stack.tags).toEqual({
      Project: 'ClearFin',
      Environment: 'prod',
      Component: 'compute',
    });
  });

  it('references NetworkingStack and SecurityStack', () => {
    expect(stack.networkingStack).toBe(networkingStack);
    expect(stack.securityStack).toBe(securityStack);
  });
});

// ── SecurityStack ───────────────────────────────────────────────────

describe('ClearFinSecurityStack', () => {
  const stack = new ClearFinSecurityStack(testContext);

  it('snapshot: full synthesized configuration', () => {
    expect({
      stackName: stack.stackName,
      tags: stack.tags,
      iamConfig: stack.iamConfig,
      cloudTrailConfig: stack.cloudTrailConfig,
    }).toMatchSnapshot();
  });

  it('tags include Project, Environment, and Component', () => {
    expect(stack.tags).toEqual({
      Project: 'ClearFin',
      Environment: 'prod',
      Component: 'security',
    });
  });

  it('iamConfig and cloudTrailConfig are present', () => {
    expect(stack.iamConfig).toBeDefined();
    expect(stack.cloudTrailConfig).toBeDefined();
  });
});

// ── StaticHostingStack ──────────────────────────────────────────────

describe('ClearFinStaticHostingStack', () => {
  const stack = new ClearFinStaticHostingStack(testContext);

  it('snapshot: full synthesized configuration', () => {
    expect({
      stackName: stack.stackName,
      tags: stack.tags,
      cloudFrontConfig: stack.cloudFrontConfig,
    }).toMatchSnapshot();
  });

  it('tags include Project, Environment, and Component', () => {
    expect(stack.tags).toEqual({
      Project: 'ClearFin',
      Environment: 'prod',
      Component: 'static-hosting',
    });
  });

  it('cloudFrontConfig is present', () => {
    expect(stack.cloudFrontConfig).toBeDefined();
  });
});
