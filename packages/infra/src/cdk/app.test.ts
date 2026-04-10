import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { buildClearFinApp, buildContextFromEnv, DEFAULT_REGION } from './app.js';
import type { CdkStackContext } from './stacks.js';
import { ClearFinNetworkingStack, ClearFinComputeStack, ClearFinSecurityStack, ClearFinStaticHostingStack } from './stacks.js';

const testContext: CdkStackContext = {
  environment: 'dev',
  accountId: '123456789012',
  region: 'il-central-1',
  imageTag: 'abc1234',
  domainName: 'dev.clearfin.example.com',
  certificateArn: 'arn:aws:acm:il-central-1:123456789012:certificate/test-cert',
};

describe('buildClearFinApp', () => {
  it('returns all four stacks', () => {
    const app = buildClearFinApp(testContext);
    expect(app.networkingStack).toBeInstanceOf(ClearFinNetworkingStack);
    expect(app.computeStack).toBeInstanceOf(ClearFinComputeStack);
    expect(app.securityStack).toBeInstanceOf(ClearFinSecurityStack);
    expect(app.staticHostingStack).toBeInstanceOf(ClearFinStaticHostingStack);
  });

  it('wires ComputeStack dependencies to NetworkingStack and SecurityStack', () => {
    const app = buildClearFinApp(testContext);
    expect(app.computeStack.networkingStack).toBe(app.networkingStack);
    expect(app.computeStack.securityStack).toBe(app.securityStack);
  });

  it('passes imageTag through context to ComputeStack', () => {
    const app = buildClearFinApp(testContext);
    expect(app.computeStack.context.imageTag).toBe('abc1234');
  });

  it('passes the same context to all stacks', () => {
    const app = buildClearFinApp(testContext);
    expect(app.networkingStack.context).toBe(testContext);
    expect(app.securityStack.context).toBe(testContext);
    expect(app.computeStack.context).toBe(testContext);
    expect(app.staticHostingStack.context).toBe(testContext);
  });

  it('generates correct stack names for the environment', () => {
    const app = buildClearFinApp(testContext);
    expect(app.networkingStack.stackName).toBe('clearfin-dev-networking');
    expect(app.computeStack.stackName).toBe('clearfin-dev-compute');
    expect(app.securityStack.stackName).toBe('clearfin-dev-security');
    expect(app.staticHostingStack.stackName).toBe('clearfin-dev-static-hosting');
  });
});

describe('buildContextFromEnv', () => {
  const envVars = {
    CDK_ENVIRONMENT: 'staging',
    CDK_ACCOUNT_ID: '987654321098',
    CDK_REGION: 'il-central-1',
    CDK_IMAGE_TAG: 'def5678',
    CDK_DOMAIN_NAME: 'staging.clearfin.example.com',
    CDK_CERTIFICATE_ARN: 'arn:aws:acm:il-central-1:987654321098:certificate/staging-cert',
  };

  beforeEach(() => {
    Object.entries(envVars).forEach(([k, v]) => { process.env[k] = v; });
  });

  afterEach(() => {
    Object.keys(envVars).forEach((k) => { delete process.env[k]; });
  });

  it('reads all context fields from environment variables', () => {
    const ctx = buildContextFromEnv();
    expect(ctx).toEqual({
      environment: 'staging',
      accountId: '987654321098',
      region: 'il-central-1',
      imageTag: 'def5678',
      domainName: 'staging.clearfin.example.com',
      certificateArn: 'arn:aws:acm:il-central-1:987654321098:certificate/staging-cert',
    });
  });

  it('throws when a required env var is missing', () => {
    delete process.env.CDK_IMAGE_TAG;
    expect(() => buildContextFromEnv()).toThrow('Missing required environment variable: CDK_IMAGE_TAG');
  });
});

describe('DEFAULT_REGION', () => {
  it('is il-central-1', () => {
    expect(DEFAULT_REGION).toBe('il-central-1');
  });
});
