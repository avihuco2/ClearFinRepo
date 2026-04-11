#!/usr/bin/env node
// @clearfin/infra — Real CDK app entry point for cdk synth/deploy
// Reads context from CDK CLI --context flags passed by the GitHub Actions workflow
// Validates: Requirements 8.1, 8.2, 8.3, 8.4, 8.5, 9.4, 10.1, 10.4

import * as cdk from 'aws-cdk-lib';
import { NetworkingCdkStack } from './networking-stack';
import { SecurityCdkStack } from './security-stack';
import { ComputeCdkStack } from './compute-stack';
import { StaticHostingCdkStack } from './static-hosting-stack';
import { buildVpcConfig } from '../vpc';
import { buildIamConfig } from '../iam';
import { buildCloudTrailConfig } from '../cloudtrail';
import { buildEcsClusterConfig } from '../ecs';
import { buildEcrRepositoryConfigs } from '../ecr';
import { buildAlbConfig } from '../alb';
import { buildCloudFrontConfig } from '../cloudfront';

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
// Pass string-based ARNs/IDs instead of direct construct references to
// avoid CDK dependency cycles. ComputeStack imports them internally
// using fromXxxArn/fromXxxAttributes with { mutable: false }.
const computeStack = new ComputeCdkStack(app, `clearfin-${environment}-compute`, {
  env,
  clearfinEnv: environment,
  accountId,
  imageTag,
  certificateArn,
  ecsClusterConfig: buildEcsClusterConfig(environment),
  ecrRepositoryConfigs: buildEcrRepositoryConfigs(environment),
  albConfig: buildAlbConfig(environment, certificateArn),
  vpcId: networkingStack.vpc.vpcId,
  availabilityZones: ['il-central-1a', 'il-central-1b'],
  privateSubnetIds: networkingStack.privateSubnets.map(s => s.subnetId),
  publicSubnetIds: networkingStack.publicSubnets.map(s => s.subnetId),
  taskExecutionRoleArns: Object.fromEntries(
    Object.entries(securityStack.taskExecutionRoles).map(([k, v]) => [k, v.roleArn]),
  ),
  taskRoleArns: Object.fromEntries(
    Object.entries(securityStack.taskRoles).map(([k, v]) => [k, v.roleArn]),
  ),
  kmsKeyArn: securityStack.kmsKey.keyArn,
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
