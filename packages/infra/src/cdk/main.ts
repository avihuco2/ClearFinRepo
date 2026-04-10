#!/usr/bin/env node
// @clearfin/infra — Real CDK app entry point for cdk synth/deploy
// Reads context from CDK CLI --context flags passed by the GitHub Actions workflow

import * as cdk from 'aws-cdk-lib';
import { ClearFinCdkStack } from './cdk-stack';

const app = new cdk.App();

const environment = app.node.tryGetContext('environment') ?? 'dev';
const accountId = app.node.tryGetContext('accountId') ?? process.env['CDK_DEFAULT_ACCOUNT'] ?? '';
const region = app.node.tryGetContext('region') ?? 'il-central-1';
const imageTag = app.node.tryGetContext('imageTag') ?? 'latest';
const domainName = app.node.tryGetContext('domainName') ?? '';
const certificateArn = app.node.tryGetContext('certificateArn') ?? '';

const env: cdk.Environment = { account: accountId, region };

// Create the four stacks matching the names used in deploy.yml
new ClearFinCdkStack(app, `clearfin-${environment}-networking`, {
  env,
  component: 'networking',
  clearfinEnv: environment,
  accountId,
  imageTag,
  domainName,
  certificateArn,
  tags: { Project: 'ClearFin', Environment: environment, Component: 'networking' },
});

new ClearFinCdkStack(app, `clearfin-${environment}-security`, {
  env,
  component: 'security',
  clearfinEnv: environment,
  accountId,
  imageTag,
  domainName,
  certificateArn,
  tags: { Project: 'ClearFin', Environment: environment, Component: 'security' },
});

new ClearFinCdkStack(app, `clearfin-${environment}-compute`, {
  env,
  component: 'compute',
  clearfinEnv: environment,
  accountId,
  imageTag,
  domainName,
  certificateArn,
  tags: { Project: 'ClearFin', Environment: environment, Component: 'compute' },
});

new ClearFinCdkStack(app, `clearfin-${environment}-static-hosting`, {
  env,
  component: 'static-hosting',
  clearfinEnv: environment,
  accountId,
  imageTag,
  domainName,
  certificateArn,
  tags: { Project: 'ClearFin', Environment: environment, Component: 'static-hosting' },
});

app.synth();
