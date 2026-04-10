// @clearfin/infra — CDK stack definitions consuming existing config builders
// Validates: Requirements 4.2, 8.2, 8.3

import { buildVpcConfig } from '../vpc.js';
import type { VpcConfig } from '../vpc.js';
import { buildEcsClusterConfig } from '../ecs.js';
import type { EcsClusterConfig } from '../ecs.js';
import { buildEcrRepositoryConfigs } from '../ecr.js';
import type { EcrRepositoryConfig } from '../ecr.js';
import { buildAlbConfig } from '../alb.js';
import type { AlbConfig } from '../alb.js';
import { buildIamConfig } from '../iam.js';
import type { IamConfig } from '../iam.js';
import { buildCloudTrailConfig } from '../cloudtrail.js';
import type { CloudTrailConfig } from '../cloudtrail.js';
import { buildCloudFrontConfig } from '../cloudfront.js';
import type { CloudFrontConfig } from '../cloudfront.js';

export interface CdkStackContext {
  environment: string;
  accountId: string;
  region: string;
  imageTag: string;
  domainName: string;
  certificateArn: string;
}

interface StackTags {
  Project: string;
  Environment: string;
  Component: string;
}

/**
 * Networking stack: VPC, subnets, NAT Gateways, VPC PrivateLink endpoints.
 * Consumes buildVpcConfig().
 */
export class ClearFinNetworkingStack {
  public readonly stackName: string;
  public readonly tags: StackTags;
  public readonly vpcConfig: VpcConfig;

  constructor(public readonly context: CdkStackContext) {
    this.stackName = `clearfin-${context.environment}-networking`;
    this.tags = {
      Project: 'ClearFin',
      Environment: context.environment,
      Component: 'networking',
    };
    this.vpcConfig = buildVpcConfig(context.environment);
  }
}

/**
 * Compute stack: ECS Fargate cluster, ECR repositories, ALB.
 * Depends on NetworkingStack (VPC/subnets) and SecurityStack (IAM roles).
 * Consumes buildEcsClusterConfig(), buildEcrRepositoryConfigs(), buildAlbConfig().
 */
export class ClearFinComputeStack {
  public readonly stackName: string;
  public readonly tags: StackTags;
  public readonly ecsClusterConfig: EcsClusterConfig;
  public readonly ecrRepositoryConfigs: EcrRepositoryConfig[];
  public readonly albConfig: AlbConfig;

  constructor(
    public readonly context: CdkStackContext,
    public readonly networkingStack: ClearFinNetworkingStack,
    public readonly securityStack: ClearFinSecurityStack,
  ) {
    this.stackName = `clearfin-${context.environment}-compute`;
    this.tags = {
      Project: 'ClearFin',
      Environment: context.environment,
      Component: 'compute',
    };
    this.ecsClusterConfig = buildEcsClusterConfig(context.environment);
    this.ecrRepositoryConfigs = buildEcrRepositoryConfigs(context.environment);
    this.albConfig = buildAlbConfig(context.environment, context.certificateArn);
  }
}

/**
 * Security stack: IAM roles, KMS keys, CloudTrail.
 * Consumes buildIamConfig(), buildCloudTrailConfig().
 */
export class ClearFinSecurityStack {
  public readonly stackName: string;
  public readonly tags: StackTags;
  public readonly iamConfig: IamConfig;
  public readonly cloudTrailConfig: CloudTrailConfig;

  constructor(public readonly context: CdkStackContext) {
    this.stackName = `clearfin-${context.environment}-security`;
    this.tags = {
      Project: 'ClearFin',
      Environment: context.environment,
      Component: 'security',
    };
    this.iamConfig = buildIamConfig(context.environment, context.accountId, context.region);
    this.cloudTrailConfig = buildCloudTrailConfig(context.environment, context.accountId, context.region);
  }
}

/**
 * Static hosting stack: S3 bucket + CloudFront distribution for Login Page.
 * Consumes buildCloudFrontConfig().
 */
export class ClearFinStaticHostingStack {
  public readonly stackName: string;
  public readonly tags: StackTags;
  public readonly cloudFrontConfig: CloudFrontConfig;

  constructor(public readonly context: CdkStackContext) {
    this.stackName = `clearfin-${context.environment}-static-hosting`;
    this.tags = {
      Project: 'ClearFin',
      Environment: context.environment,
      Component: 'static-hosting',
    };
    this.cloudFrontConfig = buildCloudFrontConfig(
      context.environment,
      `https://${context.domainName}`,
    );
  }
}
