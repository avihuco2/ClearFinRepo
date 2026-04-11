// @clearfin/infra — ComputeCdkStack: ECR repositories, ECS Fargate cluster/services, ALB
// Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.5, 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7

import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as ecr from 'aws-cdk-lib/aws-ecr';
import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as kms from 'aws-cdk-lib/aws-kms';
import { Construct } from 'constructs';
import type { EcsClusterConfig } from '../ecs.js';
import type { EcrRepositoryConfig } from '../ecr.js';
import type { AlbConfig } from '../alb.js';

export interface ComputeCdkStackProps extends cdk.StackProps {
  clearfinEnv: string;
  accountId: string;
  imageTag: string;
  certificateArn: string;
  ecsClusterConfig: EcsClusterConfig;
  ecrRepositoryConfigs: EcrRepositoryConfig[];
  albConfig: AlbConfig;
  vpc: ec2.IVpc;
  privateSubnets: ec2.ISubnet[];
  publicSubnets: ec2.ISubnet[];
  taskExecutionRoles: Record<string, iam.IRole>;
  taskRoles: Record<string, iam.IRole>;
  kmsKey: kms.IKey;
}

export class ComputeCdkStack extends cdk.Stack {
  public readonly ecrRepositories: Record<string, ecr.Repository>;
  public readonly ecsCluster: ecs.Cluster;
  public readonly fargateServices: Record<string, ecs.FargateService>;
  public readonly alb: elbv2.ApplicationLoadBalancer;

  constructor(scope: Construct, id: string, props: ComputeCdkStackProps) {
    super(scope, id, props);

    const {
      clearfinEnv,
      imageTag,
      certificateArn,
      ecsClusterConfig,
      ecrRepositoryConfigs,
      albConfig,
      vpc,
      privateSubnets,
      publicSubnets,
      taskExecutionRoles,
      taskRoles,
      kmsKey,
    } = props;

    // ─── Tags ──────────────────────────────────────────────────────────
    // Req 2.5: Apply ECR repository tags
    for (const ecrCfg of ecrRepositoryConfigs) {
      for (const [key, value] of Object.entries(ecrCfg.tags)) {
        cdk.Tags.of(this).add(key, value);
      }
    }
    // Req 3.7: Apply ECS cluster tags
    for (const [key, value] of Object.entries(ecsClusterConfig.tags)) {
      cdk.Tags.of(this).add(key, value);
    }
    // Req 4.7: Apply ALB tags
    for (const [key, value] of Object.entries(albConfig.tags)) {
      cdk.Tags.of(this).add(key, value);
    }

    // ─── ECR Repositories ──────────────────────────────────────────────
    // Req 2.1, 2.2, 2.3, 2.4, 2.5: ECR repos with immutable tags, scan-on-push, KMS, lifecycle rules
    this.ecrRepositories = {};

    for (const ecrCfg of ecrRepositoryConfigs) {
      const repoId = ecrCfg.name.replace(/\//g, '-');

      const repository = new ecr.Repository(this, `EcrRepo-${repoId}`, {
        repositoryName: ecrCfg.name,
        imageTagMutability: ecr.TagMutability.IMMUTABLE,
        imageScanOnPush: ecrCfg.scanOnPush,
        encryptionKey: kmsKey,
        removalPolicy: cdk.RemovalPolicy.RETAIN,
      });

      // Req 2.4: Lifecycle rules — retain last 10 tagged, expire untagged after 7 days
      for (const rule of ecrCfg.lifecycleRules) {
        if (rule.tagStatus === 'tagged') {
          repository.addLifecycleRule({
            description: rule.description,
            tagStatus: ecr.TagStatus.ANY,
            maxImageCount: rule.countNumber,
          });
        } else if (rule.tagStatus === 'untagged') {
          repository.addLifecycleRule({
            description: rule.description,
            tagStatus: ecr.TagStatus.UNTAGGED,
            maxImageAge: cdk.Duration.days(rule.countNumber),
          });
        }
      }

      // Apply per-repo tags
      for (const [key, value] of Object.entries(ecrCfg.tags)) {
        cdk.Tags.of(repository).add(key, value);
      }

      this.ecrRepositories[ecrCfg.name] = repository;
    }

    // ─── ECS Cluster ───────────────────────────────────────────────────
    // Req 3.1: ECS Fargate cluster with Container Insights
    this.ecsCluster = new ecs.Cluster(this, 'EcsCluster', {
      clusterName: ecsClusterConfig.name,
      vpc,
      containerInsights: ecsClusterConfig.containerInsights,
    });

    // ─── ALB Security Group ────────────────────────────────────────────
    // Req 4.6: Security group allowing inbound 443 and 80 from 0.0.0.0/0
    const albSecurityGroup = new ec2.SecurityGroup(this, 'AlbSecurityGroup', {
      vpc,
      description: `Security group for ${albConfig.name}`,
      allowAllOutbound: true,
    });

    for (const port of albConfig.securityGroupRules.ingressPorts) {
      albSecurityGroup.addIngressRule(
        ec2.Peer.ipv4(albConfig.securityGroupRules.ingressCidr),
        ec2.Port.tcp(port),
        `Allow inbound on port ${port}`,
      );
    }

    // ─── Application Load Balancer ─────────────────────────────────────
    // Req 4.1: Internet-facing ALB in public subnets
    this.alb = new elbv2.ApplicationLoadBalancer(this, 'Alb', {
      loadBalancerName: albConfig.name,
      vpc,
      internetFacing: true,
      vpcSubnets: { subnets: publicSubnets },
      securityGroup: albSecurityGroup,
    });

    // Apply ALB tags
    for (const [key, value] of Object.entries(albConfig.tags)) {
      cdk.Tags.of(this.alb).add(key, value);
    }

    // ─── HTTP Redirect Listener ────────────────────────────────────────
    // Req 4.3: HTTP listener on port 80 redirecting to HTTPS with 301
    this.alb.addListener('HttpListener', {
      port: albConfig.httpRedirectListener.port,
      protocol: elbv2.ApplicationProtocol.HTTP,
      defaultAction: elbv2.ListenerAction.redirect({
        protocol: 'HTTPS',
        port: '443',
        permanent: true,
      }),
    });

    // ─── HTTPS Listener ────────────────────────────────────────────────
    // Req 4.2: HTTPS listener on port 443 with TLS policy and ACM certificate
    const httpsListenerCfg = albConfig.listeners[0];
    const httpsListener = this.alb.addListener('HttpsListener', {
      port: httpsListenerCfg.port,
      protocol: elbv2.ApplicationProtocol.HTTPS,
      sslPolicy: elbv2.SslPolicy.RECOMMENDED_TLS,
      certificates: [elbv2.ListenerCertificate.fromArn(certificateArn)],
      open: false,
    });

    // ─── Fargate Services, Target Groups, and Listener Rules ───────────
    // Req 3.2–3.6, 4.4, 4.5: Task definitions, services, target groups, registration
    this.fargateServices = {};

    for (let i = 0; i < ecsClusterConfig.services.length; i++) {
      const svcCfg = ecsClusterConfig.services[i];
      const taskDefCfg = svcCfg.taskDefinition;
      const tgCfg = albConfig.targetGroups[i];

      // Look up the ECR repository for this service's container image
      const ecrRepo = this.ecrRepositories[taskDefCfg.ecrRepository];

      // Req 3.5: Assign execution role and task role from SecurityCdkStack
      const executionRole = taskExecutionRoles[taskDefCfg.executionRoleName];
      const taskRole = taskRoles[taskDefCfg.taskRoleName];

      // Req 3.2: Fargate task definition with CPU, memory, container port, non-root user
      const taskDef = new ecs.FargateTaskDefinition(this, `TaskDef-${svcCfg.name}`, {
        family: taskDefCfg.family,
        cpu: taskDefCfg.cpu,
        memoryLimitMiB: taskDefCfg.memory,
        executionRole,
        taskRole,
      });

      // Req 3.4: Container image from ECR repository with imageTag
      const container = taskDef.addContainer(`Container-${svcCfg.name}`, {
        image: ecs.ContainerImage.fromEcrRepository(ecrRepo, imageTag),
        containerName: svcCfg.name,
        portMappings: [{ containerPort: taskDefCfg.containerPort }],
        user: taskDefCfg.user,
        environment: taskDefCfg.environment,
        logging: ecs.LogDrivers.awsLogs({
          streamPrefix: svcCfg.name,
        }),
        // Req 3.6: Health check using the health check path
        healthCheck: {
          command: ['CMD-SHELL', `curl -f http://localhost:${taskDefCfg.containerPort}${taskDefCfg.healthCheckPath} || exit 1`],
          interval: cdk.Duration.seconds(30),
          timeout: cdk.Duration.seconds(5),
          retries: 3,
          startPeriod: cdk.Duration.seconds(60),
        },
      });

      // Req 3.3: Fargate service in private subnets with no public IP
      const fargateService = new ecs.FargateService(this, `Service-${svcCfg.name}`, {
        serviceName: svcCfg.name,
        cluster: this.ecsCluster,
        taskDefinition: taskDef,
        desiredCount: svcCfg.desiredCount,
        assignPublicIp: svcCfg.assignPublicIp,
        vpcSubnets: { subnets: privateSubnets },
      });

      this.fargateServices[svcCfg.name] = fargateService;

      // Req 4.4: Target group with health check settings
      const targetGroup = new elbv2.ApplicationTargetGroup(this, `TargetGroup-${tgCfg.name}`, {
        targetGroupName: tgCfg.name,
        vpc,
        port: tgCfg.port,
        protocol: elbv2.ApplicationProtocol.HTTP,
        targetType: elbv2.TargetType.IP,
        healthCheck: {
          path: tgCfg.healthCheck.path,
          protocol: elbv2.Protocol.HTTP,
          port: String(tgCfg.healthCheck.port),
          healthyThresholdCount: tgCfg.healthCheck.healthyThreshold,
          unhealthyThresholdCount: tgCfg.healthCheck.unhealthyThreshold,
          interval: cdk.Duration.seconds(tgCfg.healthCheck.intervalSeconds),
          timeout: cdk.Duration.seconds(tgCfg.healthCheck.timeoutSeconds),
        },
      });

      // Req 4.5: Register Fargate service with its target group
      fargateService.attachToApplicationTargetGroup(targetGroup);

      // Apply target group tags
      for (const [key, value] of Object.entries(albConfig.tags)) {
        cdk.Tags.of(targetGroup).add(key, value);
      }

      // Req 4.2: First target group is the default action for HTTPS listener,
      // additional target groups use path-based routing
      if (i === 0) {
        httpsListener.addTargetGroups(`DefaultTG`, {
          targetGroups: [targetGroup],
        });
      } else {
        // Add as additional target group with a priority-based rule
        // Use path pattern based on service name for routing
        httpsListener.addTargetGroups(`TG-${tgCfg.name}`, {
          targetGroups: [targetGroup],
          priority: i * 10,
          conditions: [elbv2.ListenerCondition.pathPatterns([`/${svcCfg.name.replace('clearfin-', '')}/*`])],
        });
      }
    }
  }
}
