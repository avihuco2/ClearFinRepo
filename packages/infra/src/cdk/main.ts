#!/usr/bin/env node
// @clearfin/infra — Real CDK app entry point for cdk synth/deploy
// Reads context from CDK CLI --context flags passed by the GitHub Actions workflow
// Validates: Requirements 8.1, 8.2, 8.3, 8.4, 8.5, 9.4, 10.1, 10.4

import * as cdk from 'aws-cdk-lib';
import { NetworkingCdkStack } from './networking-stack.js';
import { SecurityCdkStack } from './security-stack.js';
import { ComputeCdkStack } from './compute-stack.js';
import { StaticHostingCdkStack } from './static-hosting-stack.js';
import { buildVpcConfig } from '../vpc.js';
import { buildIamConfig } from '../iam.js';
import { buildCloudTrailConfig } from '../cloudtrail.js';
import { buildEcsClusterConfig } from '../ecs.js';
import { buildEcrRepositoryConfigs } from '../ecr.js';
import { buildAlbConfig } from '../alb.js';
import { buildCloudFrontConfig } from '../cloudfront.js';

const app = new cdk.App();

const environment = app.node.tryGetContext('environment') ?? 'dev';
const accountId = app.node.tryGetContext('accountId') ?? process.env['CDK_DEFAULT_ACCOUNT'] ?? '';
const region = app.node.tryGetContext('region') ?? 'il-central-1';
const imageTag = app.node.tryGetContext('imageTag') ?? 'latest';
const domainName = app.node.tryGetContext('domainName') ?? '';
const certificateArn = app.node.tryGetContext('certificateArn') ?? '';

const env: cdk.Environment | undefined = accountId
  ? { account: accountId, region }
  : undefined;

// ─── 1. NetworkingCdkStack (no dependencies) ──────────────────────────
// Req 8.1: Instantiate with environment context
const networkingStack = new NetworkingCdkStack(app, `clearfin-${environment}-networking`, {
  env,
  clearfinEnv: environment,
  vpcConfig: buildVpcConfig(environment),
  tags: { Project: 'ClearFin', Environment: environment, Component: 'networking' },
});

// ─── 2. SecurityCdkStack (no dependencies) ─────────────────────────────
// Req 8.1: Instantiate with environment context
const securityStack = new SecurityCdkStack(app, `clearfin-${environment}-security`, {
  env,
  clearfinEnv: environment,
  accountId,
  iamConfig: buildIamConfig(environment, accountId, region),
  cloudTrailConfig: buildCloudTrailConfig(environment, accountId, region),
  tags: { Project: 'ClearFin', Environment: environment, Component: 'security' },
});

// ─── 3. ComputeCdkStack (depends on Networking + Security) ─────────────
// Req 8.2, 8.3, 8.4: Cross-stack references from Networking and Security
const computeStack = new ComputeCdkStack(app, `clearfin-${environment}-compute`, {
  env,
  clearfinEnv: environment,
  accountId,
  imageTag,
  certificateArn,
  ecsClusterConfig: buildEcsClusterConfig(environment),
  ecrRepositoryConfigs: buildEcrRepositoryConfigs(environment),
  albConfig: buildAlbConfig(environment, certificateArn),
  vpc: networkingStack.vpc,
  privateSubnets: networkingStack.privateSubnets,
  publicSubnets: networkingStack.publicSubnets,
  taskExecutionRoles: securityStack.taskExecutionRoles,
  taskRoles: securityStack.taskRoles,
  kmsKey: securityStack.kmsKey,
  tags: { Project: 'ClearFin', Environment: environment, Component: 'compute' },
});

// Req 8.2: Explicit dependency ordering — Compute depends on Networking and Security
computeStack.addDependency(networkingStack);
computeStack.addDependency(securityStack);

// ─── 4. StaticHostingCdkStack (no dependencies) ───────────────────────
// Req 8.1: Instantiate with environment context
new StaticHostingCdkStack(app, `clearfin-${environment}-static-hosting`, {
  env,
  clearfinEnv: environment,
  cloudFrontConfig: buildCloudFrontConfig(environment, `https://${domainName}`),
  tags: { Project: 'ClearFin', Environment: environment, Component: 'static-hosting' },
});

app.synth();
