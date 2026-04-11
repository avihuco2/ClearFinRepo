// @clearfin/infra — Integration test: full app synthesis with all four stacks
// Validates: Requirements 8.1, 8.2, 8.3, 8.4, 9.1, 9.3

import { describe, it, expect, beforeAll } from 'vitest';
import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import { Template } from 'aws-cdk-lib/assertions';
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

const ENV = 'test';
const ACCOUNT_ID = '123456789012';
const REGION = 'il-central-1';
const IMAGE_TAG = 'abc1234';
const CERTIFICATE_ARN = 'arn:aws:acm:il-central-1:123456789012:certificate/test-cert';
const DOMAIN_NAME = 'test.clearfin.example.com';

let app: cdk.App;
let networkingStack: NetworkingCdkStack;
let securityStack: SecurityCdkStack;
let computeStack: ComputeCdkStack;
let staticHostingStack: StaticHostingCdkStack;
let networkingTemplate: Template;
let securityTemplate: Template;
let computeTemplate: Template;
let staticHostingTemplate: Template;

beforeAll(() => {
  app = new cdk.App();
  const cdkEnv: cdk.Environment = { account: ACCOUNT_ID, region: REGION };
  const ecsClusterConfig = buildEcsClusterConfig(ENV);

  // Req 8.1: Instantiate Networking and Security stacks (no dependencies)
  networkingStack = new NetworkingCdkStack(app, `clearfin-${ENV}-networking`, {
    env: cdkEnv,
    clearfinEnv: ENV,
    vpcConfig: buildVpcConfig(ENV),
    tags: { Project: 'ClearFin', Environment: ENV, Component: 'networking' },
  });

  securityStack = new SecurityCdkStack(app, `clearfin-${ENV}-security`, {
    env: cdkEnv,
    clearfinEnv: ENV,
    accountId: ACCOUNT_ID,
    iamConfig: buildIamConfig(ENV, ACCOUNT_ID, REGION),
    cloudTrailConfig: buildCloudTrailConfig(ENV, ACCOUNT_ID, REGION),
    tags: { Project: 'ClearFin', Environment: ENV, Component: 'security' },
  });

  // Req 8.2, 8.3, 8.4: ComputeStack with cross-stack references
  // Cross-stack refs are passed via imported ARN-based lookups to avoid CDK
  // dependency cycles (same pattern used in compute-stack.test.ts). In a real
  // deployment CDK resolves these via CloudFormation exports/imports.
  const helperStack = new cdk.Stack(app, 'HelperImports', { env: cdkEnv });

  const vpc = ec2.Vpc.fromVpcAttributes(helperStack, 'ImportedVpc', {
    vpcId: 'vpc-test123',
    availabilityZones: ['il-central-1a', 'il-central-1b'],
    publicSubnetIds: ['subnet-pub1', 'subnet-pub2'],
    privateSubnetIds: ['subnet-priv1', 'subnet-priv2'],
  });

  const privateSubnets = [
    ec2.Subnet.fromSubnetAttributes(helperStack, 'PrivSub1', {
      subnetId: 'subnet-priv1', availabilityZone: 'il-central-1a',
    }),
    ec2.Subnet.fromSubnetAttributes(helperStack, 'PrivSub2', {
      subnetId: 'subnet-priv2', availabilityZone: 'il-central-1b',
    }),
  ];

  const publicSubnets = [
    ec2.Subnet.fromSubnetAttributes(helperStack, 'PubSub1', {
      subnetId: 'subnet-pub1', availabilityZone: 'il-central-1a',
    }),
    ec2.Subnet.fromSubnetAttributes(helperStack, 'PubSub2', {
      subnetId: 'subnet-pub2', availabilityZone: 'il-central-1b',
    }),
  ];

  const taskExecutionRoles: Record<string, iam.IRole> = {};
  const taskRoles: Record<string, iam.IRole> = {};
  for (const svc of ecsClusterConfig.services) {
    const execName = svc.taskDefinition.executionRoleName;
    taskExecutionRoles[execName] = iam.Role.fromRoleArn(
      helperStack, `Import-${execName}`,
      `arn:aws:iam::${ACCOUNT_ID}:role/${execName}`,
    );
    const taskName = svc.taskDefinition.taskRoleName;
    taskRoles[taskName] = iam.Role.fromRoleArn(
      helperStack, `Import-${taskName}`,
      `arn:aws:iam::${ACCOUNT_ID}:role/${taskName}`,
    );
  }

  const kmsKeyImport = kms.Key.fromKeyArn(
    helperStack, 'ImportedKmsKey',
    `arn:aws:kms:${REGION}:${ACCOUNT_ID}:key/test-key-id`,
  );

  computeStack = new ComputeCdkStack(app, `clearfin-${ENV}-compute`, {
    env: cdkEnv,
    clearfinEnv: ENV,
    accountId: ACCOUNT_ID,
    imageTag: IMAGE_TAG,
    certificateArn: CERTIFICATE_ARN,
    ecsClusterConfig,
    ecrRepositoryConfigs: buildEcrRepositoryConfigs(ENV),
    albConfig: buildAlbConfig(ENV, CERTIFICATE_ARN),
    vpc,
    privateSubnets,
    publicSubnets,
    taskExecutionRoles,
    taskRoles,
    kmsKey: kmsKeyImport,
    tags: { Project: 'ClearFin', Environment: ENV, Component: 'compute' },
  });

  // Req 8.2: Explicit dependency ordering
  computeStack.addDependency(networkingStack);
  computeStack.addDependency(securityStack);

  staticHostingStack = new StaticHostingCdkStack(app, `clearfin-${ENV}-static-hosting`, {
    env: cdkEnv,
    clearfinEnv: ENV,
    cloudFrontConfig: buildCloudFrontConfig(ENV, `https://${DOMAIN_NAME}`),
    tags: { Project: 'ClearFin', Environment: ENV, Component: 'static-hosting' },
  });

  // Req 9.1: Synthesize the entire app
  app.synth();

  networkingTemplate = Template.fromStack(networkingStack);
  securityTemplate = Template.fromStack(securityStack);
  computeTemplate = Template.fromStack(computeStack);
  staticHostingTemplate = Template.fromStack(staticHostingStack);
});

describe('Full app synthesis', () => {
  // Req 9.1: All four stacks produce valid CloudFormation templates
  it('synthesizes all four stacks without errors', () => {
    expect(Object.keys(networkingTemplate.toJSON().Resources).length).toBeGreaterThan(0);
    expect(Object.keys(securityTemplate.toJSON().Resources).length).toBeGreaterThan(0);
    expect(Object.keys(computeTemplate.toJSON().Resources).length).toBeGreaterThan(0);
    expect(Object.keys(staticHostingTemplate.toJSON().Resources).length).toBeGreaterThan(0);
  });

  it('networking stack produces VPC and subnet resources', () => {
    networkingTemplate.resourceCountIs('AWS::EC2::VPC', 1);
    networkingTemplate.resourceCountIs('AWS::EC2::Subnet', 4);
  });

  it('security stack produces KMS key and IAM roles', () => {
    securityTemplate.resourceCountIs('AWS::KMS::Key', 1);
    securityTemplate.resourceCountIs('AWS::IAM::Role', 7);
  });

  it('compute stack produces ECS cluster, services, and ALB', () => {
    computeTemplate.resourceCountIs('AWS::ECS::Cluster', 1);
    computeTemplate.resourceCountIs('AWS::ECS::Service', 3);
    computeTemplate.resourceCountIs('AWS::ElasticLoadBalancingV2::LoadBalancer', 1);
  });

  it('static hosting stack produces S3 bucket and CloudFront distribution', () => {
    staticHostingTemplate.resourceCountIs('AWS::S3::Bucket', 1);
    staticHostingTemplate.resourceCountIs('AWS::CloudFront::Distribution', 1);
  });
});

describe('Cross-stack references', () => {
  // Req 8.3, 8.4: Networking and Security stacks export values for Compute
  it('networking stack exports VPC ID, public subnet IDs, and private subnet IDs', () => {
    const outputs = networkingTemplate.toJSON().Outputs ?? {};
    const exportNames = Object.values(outputs).map((o: any) => o.Export?.Name).filter(Boolean);
    expect(exportNames).toContain(`${ENV}-vpc-id`);
    expect(exportNames).toContain(`${ENV}-public-subnet-ids`);
    expect(exportNames).toContain(`${ENV}-private-subnet-ids`);
  });

  it('security stack exports KMS key ARN', () => {
    const outputs = securityTemplate.toJSON().Outputs ?? {};
    const exportNames = Object.values(outputs).map((o: any) => o.Export?.Name).filter(Boolean);
    expect(exportNames).toContain(`${ENV}-kms-key-arn`);
  });

  it('security stack exports IAM role ARNs', () => {
    const outputs = securityTemplate.toJSON().Outputs ?? {};
    const exportNames = Object.values(outputs).map((o: any) => o.Export?.Name).filter(Boolean);
    // At least execution role and task role exports
    const roleExports = exportNames.filter((n: string) => n.includes('execution') || n.includes('task'));
    expect(roleExports.length).toBeGreaterThanOrEqual(1);
  });
});

describe('Stack dependency ordering', () => {
  // Req 8.2: Compute depends on Networking and Security
  it('compute stack depends on networking stack', () => {
    const deps = computeStack.dependencies;
    expect(deps.some((d) => d.stackName === networkingStack.stackName)).toBe(true);
  });

  it('compute stack depends on security stack', () => {
    const deps = computeStack.dependencies;
    expect(deps.some((d) => d.stackName === securityStack.stackName)).toBe(true);
  });

  it('networking stack has no dependencies', () => {
    expect(networkingStack.dependencies).toHaveLength(0);
  });

  it('security stack has no dependencies', () => {
    expect(securityStack.dependencies).toHaveLength(0);
  });

  it('static hosting stack has no dependencies', () => {
    expect(staticHostingStack.dependencies).toHaveLength(0);
  });
});

describe('Config builder integration', () => {
  // Req 9.3: Config builder changes flow through to synthesized templates
  it('networking stack uses VPC CIDR from buildVpcConfig', () => {
    networkingTemplate.hasResourceProperties('AWS::EC2::VPC', {
      CidrBlock: '10.0.0.0/16',
    });
  });

  it('compute stack uses ECS cluster name from buildEcsClusterConfig', () => {
    computeTemplate.hasResourceProperties('AWS::ECS::Cluster', {
      ClusterName: `clearfin-${ENV}-cluster`,
    });
  });

  it('compute stack uses certificate ARN from context', () => {
    computeTemplate.hasResourceProperties('AWS::ElasticLoadBalancingV2::Listener', {
      Port: 443,
      Certificates: [{ CertificateArn: CERTIFICATE_ARN }],
    });
  });
});
