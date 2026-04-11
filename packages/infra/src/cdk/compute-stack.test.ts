// @clearfin/infra — CDK assertion tests for ComputeCdkStack
// Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.5, 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 9.1

import { describe, it, expect, beforeAll } from 'vitest';
import * as cdk from 'aws-cdk-lib';
import { Template, Match } from 'aws-cdk-lib/assertions';
import { ComputeCdkStack } from './compute-stack.js';
import { buildEcsClusterConfig } from '../ecs.js';
import { buildEcrRepositoryConfigs } from '../ecr.js';
import { buildAlbConfig } from '../alb.js';

const ENV = 'test';
const ACCOUNT_ID = '123456789012';
const REGION = 'il-central-1';
const CERTIFICATE_ARN = 'arn:aws:acm:il-central-1:123456789012:certificate/test-cert';
const IMAGE_TAG = 'latest';

let template: Template;

/**
 * Creates a self-contained ComputeCdkStack for testing.
 *
 * All cross-stack dependencies (VPC, subnets, IAM roles, KMS key) are
 * passed as string ARNs/IDs. ComputeCdkStack imports them internally
 * using fromXxxArn/fromXxxAttributes with { mutable: false }, avoiding
 * CDK cross-stack dependency cycles.
 */
function buildTestStack(): ComputeCdkStack {
  const app = new cdk.App();
  const ecsClusterConfig = buildEcsClusterConfig(ENV);

  const taskExecutionRoleArns: Record<string, string> = {};
  const taskRoleArns: Record<string, string> = {};
  for (const svc of ecsClusterConfig.services) {
    const execName = svc.taskDefinition.executionRoleName;
    taskExecutionRoleArns[execName] = `arn:aws:iam::${ACCOUNT_ID}:role/${execName}`;
    const taskName = svc.taskDefinition.taskRoleName;
    taskRoleArns[taskName] = `arn:aws:iam::${ACCOUNT_ID}:role/${taskName}`;
  }

  const computeStack = new ComputeCdkStack(app, 'RealComputeStack', {
    env: { account: ACCOUNT_ID, region: REGION },
    clearfinEnv: ENV,
    accountId: ACCOUNT_ID,
    imageTag: IMAGE_TAG,
    certificateArn: CERTIFICATE_ARN,
    ecsClusterConfig,
    ecrRepositoryConfigs: buildEcrRepositoryConfigs(ENV),
    albConfig: buildAlbConfig(ENV, CERTIFICATE_ARN),
    vpcId: 'vpc-test123',
    availabilityZones: ['il-central-1a', 'il-central-1b'],
    privateSubnetIds: ['subnet-priv1', 'subnet-priv2'],
    publicSubnetIds: ['subnet-pub1', 'subnet-pub2'],
    taskExecutionRoleArns,
    taskRoleArns,
    kmsKeyArn: `arn:aws:kms:${REGION}:${ACCOUNT_ID}:key/test-key-id`,
  });

  return computeStack;
}

beforeAll(() => {
  template = Template.fromStack(buildTestStack());
});


describe('ECR Repositories', () => {
  it('creates 3 ECR repositories', () => {
    template.resourceCountIs('AWS::ECR::Repository', 3);
  });

  it('creates ECR repository for auth-service with immutable tags', () => {
    template.hasResourceProperties('AWS::ECR::Repository', {
      RepositoryName: 'clearfin/auth-service',
      ImageTagMutability: 'IMMUTABLE',
    });
  });

  it('creates ECR repository for sts-broker with immutable tags', () => {
    template.hasResourceProperties('AWS::ECR::Repository', {
      RepositoryName: 'clearfin/sts-broker',
      ImageTagMutability: 'IMMUTABLE',
    });
  });

  it('creates ECR repository for secrets-hierarchy-manager with immutable tags', () => {
    template.hasResourceProperties('AWS::ECR::Repository', {
      RepositoryName: 'clearfin/secrets-hierarchy-manager',
      ImageTagMutability: 'IMMUTABLE',
    });
  });

  it('all ECR repositories have scan-on-push enabled', () => {
    const repos = template.findResources('AWS::ECR::Repository');
    for (const [, resource] of Object.entries(repos)) {
      expect((resource as any).Properties.ImageScanningConfiguration.ScanOnPush).toBe(true);
    }
  });

  it('all ECR repositories have KMS encryption', () => {
    const repos = template.findResources('AWS::ECR::Repository');
    for (const [, resource] of Object.entries(repos)) {
      expect((resource as any).Properties.EncryptionConfiguration.EncryptionType).toBe('KMS');
    }
  });
});

describe('ECS Cluster', () => {
  it('creates exactly 1 ECS cluster', () => { template.resourceCountIs('AWS::ECS::Cluster', 1); });
  it('creates ECS cluster with the correct name', () => {
    template.hasResourceProperties('AWS::ECS::Cluster', { ClusterName: `clearfin-${ENV}-cluster` });
  });
  it('creates ECS cluster with Container Insights enabled', () => {
    template.hasResourceProperties('AWS::ECS::Cluster', {
      ClusterSettings: Match.arrayWith([Match.objectLike({ Name: 'containerInsights', Value: 'enabled' })]),
    });
  });
});

describe('Fargate Task Definitions', () => {
  it('creates 3 Fargate task definitions', () => { template.resourceCountIs('AWS::ECS::TaskDefinition', 3); });

  it('creates task definition for auth-service with correct CPU and memory', () => {
    template.hasResourceProperties('AWS::ECS::TaskDefinition', {
      Family: `clearfin-${ENV}-auth-service`, Cpu: '256', Memory: '512',
      NetworkMode: 'awsvpc', RequiresCompatibilities: ['FARGATE'],
    });
  });

  it('creates task definition for sts-broker with correct CPU and memory', () => {
    template.hasResourceProperties('AWS::ECS::TaskDefinition', {
      Family: `clearfin-${ENV}-sts-broker`, Cpu: '256', Memory: '512',
      NetworkMode: 'awsvpc', RequiresCompatibilities: ['FARGATE'],
    });
  });

  it('creates task definition for secrets-hierarchy-manager with correct CPU and memory', () => {
    template.hasResourceProperties('AWS::ECS::TaskDefinition', {
      Family: `clearfin-${ENV}-secrets-hierarchy-manager`, Cpu: '256', Memory: '512',
      NetworkMode: 'awsvpc', RequiresCompatibilities: ['FARGATE'],
    });
  });

  it('task definitions have container definitions with correct ports', () => {
    template.hasResourceProperties('AWS::ECS::TaskDefinition', {
      Family: `clearfin-${ENV}-auth-service`,
      ContainerDefinitions: Match.arrayWith([Match.objectLike({
        PortMappings: Match.arrayWith([Match.objectLike({ ContainerPort: 3000 })]),
      })]),
    });
    template.hasResourceProperties('AWS::ECS::TaskDefinition', {
      Family: `clearfin-${ENV}-sts-broker`,
      ContainerDefinitions: Match.arrayWith([Match.objectLike({
        PortMappings: Match.arrayWith([Match.objectLike({ ContainerPort: 3001 })]),
      })]),
    });
    template.hasResourceProperties('AWS::ECS::TaskDefinition', {
      Family: `clearfin-${ENV}-secrets-hierarchy-manager`,
      ContainerDefinitions: Match.arrayWith([Match.objectLike({
        PortMappings: Match.arrayWith([Match.objectLike({ ContainerPort: 3002 })]),
      })]),
    });
  });

  it('task definitions use non-root user', () => {
    template.hasResourceProperties('AWS::ECS::TaskDefinition', {
      ContainerDefinitions: Match.arrayWith([Match.objectLike({ User: '1000:1000' })]),
    });
  });
});

describe('Fargate Services', () => {
  it('creates 3 Fargate services', () => { template.resourceCountIs('AWS::ECS::Service', 3); });

  it('Fargate services have no public IP assignment', () => {
    const services = template.findResources('AWS::ECS::Service');
    for (const [, resource] of Object.entries(services)) {
      const awsvpc = (resource as any).Properties.NetworkConfiguration?.AwsvpcConfiguration;
      expect(awsvpc.AssignPublicIp).toBe('DISABLED');
    }
  });

  it('Fargate services are placed in private subnets', () => {
    const services = template.findResources('AWS::ECS::Service');
    for (const [, resource] of Object.entries(services)) {
      const awsvpc = (resource as any).Properties.NetworkConfiguration?.AwsvpcConfiguration;
      expect(awsvpc.Subnets).toBeDefined();
      expect(awsvpc.Subnets.length).toBe(2);
    }
  });

  it('creates service for clearfin-auth-service', () => {
    template.hasResourceProperties('AWS::ECS::Service', { ServiceName: 'clearfin-auth-service', LaunchType: 'FARGATE' });
  });
  it('creates service for clearfin-sts-broker', () => {
    template.hasResourceProperties('AWS::ECS::Service', { ServiceName: 'clearfin-sts-broker', LaunchType: 'FARGATE' });
  });
  it('creates service for clearfin-secrets-hierarchy-manager', () => {
    template.hasResourceProperties('AWS::ECS::Service', { ServiceName: 'clearfin-secrets-hierarchy-manager', LaunchType: 'FARGATE' });
  });
});

describe('Application Load Balancer', () => {
  it('creates exactly 1 ALB', () => { template.resourceCountIs('AWS::ElasticLoadBalancingV2::LoadBalancer', 1); });
  it('creates an internet-facing ALB', () => {
    template.hasResourceProperties('AWS::ElasticLoadBalancingV2::LoadBalancer', { Scheme: 'internet-facing', Type: 'application' });
  });
  it('ALB has the correct name', () => {
    template.hasResourceProperties('AWS::ElasticLoadBalancingV2::LoadBalancer', { Name: `clearfin-${ENV}-alb` });
  });
  it('ALB is placed in subnets', () => {
    template.hasResourceProperties('AWS::ElasticLoadBalancingV2::LoadBalancer', { Subnets: Match.anyValue() });
  });
});

describe('HTTPS Listener', () => {
  it('creates HTTPS listener on port 443', () => {
    template.hasResourceProperties('AWS::ElasticLoadBalancingV2::Listener', { Port: 443, Protocol: 'HTTPS' });
  });
  it('HTTPS listener uses a TLS policy', () => {
    template.hasResourceProperties('AWS::ElasticLoadBalancingV2::Listener', { Port: 443, SslPolicy: Match.stringLikeRegexp('TLS') });
  });
  it('HTTPS listener has the ACM certificate', () => {
    template.hasResourceProperties('AWS::ElasticLoadBalancingV2::Listener', {
      Port: 443, Certificates: Match.arrayWith([Match.objectLike({ CertificateArn: CERTIFICATE_ARN })]),
    });
  });
});

describe('HTTP Redirect Listener', () => {
  it('creates HTTP listener on port 80', () => {
    template.hasResourceProperties('AWS::ElasticLoadBalancingV2::Listener', { Port: 80, Protocol: 'HTTP' });
  });
  it('HTTP listener redirects to HTTPS', () => {
    template.hasResourceProperties('AWS::ElasticLoadBalancingV2::Listener', {
      Port: 80,
      DefaultActions: Match.arrayWith([Match.objectLike({
        Type: 'redirect',
        RedirectConfig: Match.objectLike({ Protocol: 'HTTPS', Port: '443' }),
      })]),
    });
  });
});

describe('Target Groups', () => {
  it('creates 3 target groups', () => { template.resourceCountIs('AWS::ElasticLoadBalancingV2::TargetGroup', 3); });
  it('creates target group for auth-service on port 3000 with health check', () => {
    template.hasResourceProperties('AWS::ElasticLoadBalancingV2::TargetGroup', {
      Name: `clearfin-${ENV}-auth-tg`, Port: 3000, Protocol: 'HTTP', TargetType: 'ip',
      HealthCheckPath: '/health', HealthCheckPort: '3000',
    });
  });
  it('creates target group for sts-broker on port 3001 with health check', () => {
    template.hasResourceProperties('AWS::ElasticLoadBalancingV2::TargetGroup', {
      Name: `clearfin-${ENV}-sts-tg`, Port: 3001, Protocol: 'HTTP', TargetType: 'ip',
      HealthCheckPath: '/health', HealthCheckPort: '3001',
    });
  });
  it('creates target group for secrets-hierarchy-manager on port 3002 with health check', () => {
    template.hasResourceProperties('AWS::ElasticLoadBalancingV2::TargetGroup', {
      Name: `clearfin-${ENV}-secrets-tg`, Port: 3002, Protocol: 'HTTP', TargetType: 'ip',
      HealthCheckPath: '/health', HealthCheckPort: '3002',
    });
  });
  it('target groups have correct health check thresholds', () => {
    template.hasResourceProperties('AWS::ElasticLoadBalancingV2::TargetGroup', {
      HealthyThresholdCount: 2, UnhealthyThresholdCount: 3,
      HealthCheckIntervalSeconds: 30, HealthCheckTimeoutSeconds: 5,
    });
  });
});

describe('ALB Security Group', () => {
  it('creates a security group for the ALB', () => {
    template.hasResourceProperties('AWS::EC2::SecurityGroup', {
      GroupDescription: Match.stringLikeRegexp('Security group for clearfin-test-alb'),
    });
  });
  it('security group allows inbound on port 443 from 0.0.0.0/0', () => {
    template.hasResourceProperties('AWS::EC2::SecurityGroup', {
      SecurityGroupIngress: Match.arrayWith([
        Match.objectLike({ IpProtocol: 'tcp', FromPort: 443, ToPort: 443, CidrIp: '0.0.0.0/0' }),
      ]),
    });
  });
  it('security group allows inbound on port 80 from 0.0.0.0/0', () => {
    template.hasResourceProperties('AWS::EC2::SecurityGroup', {
      SecurityGroupIngress: Match.arrayWith([
        Match.objectLike({ IpProtocol: 'tcp', FromPort: 80, ToPort: 80, CidrIp: '0.0.0.0/0' }),
      ]),
    });
  });
});

describe('Synthesis validation', () => {
  it('synthesizes without errors using config builder output', () => {
    const resources = template.toJSON().Resources;
    expect(Object.keys(resources).length).toBeGreaterThan(0);
  });
  it('produces expected resource types and counts', () => {
    template.resourceCountIs('AWS::ECR::Repository', 3);
    template.resourceCountIs('AWS::ECS::Cluster', 1);
    template.resourceCountIs('AWS::ECS::TaskDefinition', 3);
    template.resourceCountIs('AWS::ECS::Service', 3);
    template.resourceCountIs('AWS::ElasticLoadBalancingV2::LoadBalancer', 1);
    template.resourceCountIs('AWS::ElasticLoadBalancingV2::TargetGroup', 3);
  });
  it('creates exactly 2 listeners (HTTPS + HTTP redirect)', () => {
    template.resourceCountIs('AWS::ElasticLoadBalancingV2::Listener', 2);
  });
});
