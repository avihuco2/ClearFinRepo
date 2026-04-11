# Implementation Plan: CDK Infrastructure Constructs

## Overview

Replace the placeholder `ClearFinCdkStack` with four real CDK stack classes that consume config builder outputs and create actual AWS resources. Each stack file is implemented incrementally, tested with CDK assertions, then wired together in `main.ts` with cross-stack references and dependency ordering.

## Tasks

- [x] 1. Implement NetworkingCdkStack
  - [x] 1.1 Create `packages/infra/src/cdk/networking-stack.ts`
    - Define `NetworkingCdkStackProps` extending `cdk.StackProps` with `clearfinEnv` and `vpcConfig`
    - Create `ec2.Vpc` with CIDR, DNS support, DNS hostnames from `buildVpcConfig` output
    - Create public and private `ec2.Subnet` across `il-central-1a` and `il-central-1b`
    - Create `ec2.CfnNatGateway` with `ec2.CfnEIP` per AZ in public subnets
    - Create `ec2.InterfaceVpcEndpoint` for ECR API, ECR Docker, STS, Secrets Manager, KMS, CloudWatch Logs, CloudWatch Monitoring with private DNS
    - Create `ec2.GatewayVpcEndpoint` for S3
    - Export VPC ID, public subnet IDs, private subnet IDs as `cdk.CfnOutput`
    - Apply tags from `VpcConfig` to all resources
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7_

  - [x] 1.2 Write CDK assertion tests for NetworkingCdkStack
    - Create `packages/infra/src/cdk/networking-stack.test.ts`
    - Synthesize the stack with test config, use `Template.fromStack` and `hasResourceProperties`
    - Assert VPC resource with correct CIDR and DNS settings
    - Assert subnet count and CIDR blocks for public and private subnets
    - Assert NAT Gateway and EIP resources per AZ
    - Assert all 7 interface VPC endpoints and 1 gateway endpoint
    - Assert CfnOutput exports for VPC ID, subnet IDs
    - Assert tags on networking resources
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 9.1, 9.2_

- [x] 2. Implement SecurityCdkStack
  - [x] 2.1 Create `packages/infra/src/cdk/security-stack.ts`
    - Define `SecurityCdkStackProps` extending `cdk.StackProps` with `clearfinEnv`, `accountId`, `iamConfig`, `cloudTrailConfig`
    - Create `kms.Key` with alias, automatic rotation, key policy from `buildIamConfig`
    - Create `iam.Role` for each task execution role with trust policy, managed policies, inline policies
    - Create `iam.Role` for each task role with trust policy and KMS decrypt inline policy
    - Create `iam.Role` for STS base role with trust policy allowing only sts-broker task role
    - Create `s3.Bucket` for CloudTrail logs with encryption, versioning, CloudTrail write policy
    - Create `cloudtrail.Trail` with log file validation, S3 destination, KMS encryption, event selectors
    - Create `events.Rule` for IAM policy changes, STS trust changes, Secrets Manager policy changes
    - Create `sns.Topic` for security alerts, targeted by EventBridge rules
    - Export KMS key ARN and IAM role ARNs as `cdk.CfnOutput`
    - Apply tags from `IamConfig` and `CloudTrailConfig`
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 6.1, 6.2, 6.3, 6.4, 6.5, 6.6_

  - [x] 2.2 Write CDK assertion tests for SecurityCdkStack
    - Create `packages/infra/src/cdk/security-stack.test.ts`
    - Assert KMS key with rotation enabled and correct alias
    - Assert IAM roles count and trust policies for execution roles, task roles, STS base role
    - Assert inline policies include KMS decrypt permissions
    - Assert S3 bucket for CloudTrail with encryption and versioning
    - Assert CloudTrail trail with log file validation and S3 destination
    - Assert EventBridge rules for each alert pattern
    - Assert SNS topic for security alerts
    - Assert CfnOutput exports for KMS key ARN and role ARNs
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 9.1_

- [x] 3. Checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 4. Implement ComputeCdkStack
  - [x] 4.1 Create `packages/infra/src/cdk/compute-stack.ts`
    - Define `ComputeCdkStackProps` extending `cdk.StackProps` with cross-stack references (VPC, subnets, IAM roles, KMS key) and config objects
    - Create `ecr.Repository` for each service with immutable tags, scan-on-push, KMS encryption, lifecycle rules from `buildEcrRepositoryConfigs`
    - Create `ecs.Cluster` with Container Insights enabled from `buildEcsClusterConfig`
    - Create `ecs.FargateTaskDefinition` per service with CPU, memory, container port, non-root user, health check, execution role, task role
    - Create `ecs.FargateService` per service in private subnets with no public IP and desired count
    - Reference ECR repository for each service container image using `imageTag` from context
    - Create `elbv2.ApplicationLoadBalancer` internet-facing in public subnets from `buildAlbConfig`
    - Create HTTPS listener on port 443 with TLS policy `ELBSecurityPolicy-TLS13-1-2-2021-06` and ACM certificate ARN
    - Create HTTP listener on port 80 with redirect to HTTPS (301)
    - Create `elbv2.ApplicationTargetGroup` per service with health check settings
    - Register each Fargate service with its corresponding target group
    - Create ALB security group allowing inbound 443 and 80 from `0.0.0.0/0`
    - Apply tags from `EcsClusterConfig`, `EcrRepositoryConfig`, and `AlbConfig`
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7_

  - [x] 4.2 Write CDK assertion tests for ComputeCdkStack
    - Create `packages/infra/src/cdk/compute-stack.test.ts`
    - Assert 3 ECR repositories with immutable tags and scan-on-push
    - Assert ECS cluster with Container Insights
    - Assert 3 Fargate task definitions with correct CPU, memory, container port
    - Assert 3 Fargate services in private subnets with no public IP
    - Assert ALB is internet-facing in public subnets
    - Assert HTTPS listener with correct TLS policy and certificate
    - Assert HTTP listener redirects to HTTPS with 301
    - Assert 3 target groups with health check paths on correct ports
    - Assert ALB security group allows inbound 443 and 80
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 9.1_

- [x] 5. Implement StaticHostingCdkStack
  - [x] 5.1 Create `packages/infra/src/cdk/static-hosting-stack.ts`
    - Define `StaticHostingCdkStackProps` extending `cdk.StackProps` with `clearfinEnv` and `cloudFrontConfig`
    - Create `s3.Bucket` with all public access blocked, AES-256 encryption, versioning from `buildCloudFrontConfig`
    - Create `cloudfront.Distribution` with OAC (SigV4 signing) to access S3 bucket
    - Configure redirect-to-https viewer protocol policy, HTTP/2 and HTTP/3, `index.html` default root object
    - Create `cloudfront.ResponseHeadersPolicy` with CSP, HSTS, X-Content-Type-Options, X-Frame-Options (DENY), X-XSS-Protection, Referrer-Policy
    - Configure custom error responses returning `/index.html` with HTTP 200 for 403 and 404 errors (SPA routing)
    - Apply tags from `CloudFrontConfig`
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6_

  - [x] 5.2 Write CDK assertion tests for StaticHostingCdkStack
    - Create `packages/infra/src/cdk/static-hosting-stack.test.ts`
    - Assert S3 bucket with public access blocked, encryption, versioning
    - Assert CloudFront distribution with OAC, redirect-to-https, HTTP/2+3, default root object
    - Assert response headers policy with all security headers
    - Assert custom error responses for 403 and 404
    - Assert tags on S3 bucket and CloudFront distribution
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 9.1_

- [x] 6. Checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 7. Update main.ts and wire cross-stack references
  - [x] 7.1 Update `packages/infra/src/cdk/main.ts` to instantiate real stacks
    - Replace `ClearFinCdkStack` imports with the four new stack classes
    - Instantiate `NetworkingCdkStack` and `SecurityCdkStack` first (no dependencies)
    - Instantiate `ComputeCdkStack` with cross-stack references from Networking and Security (VPC, subnets, IAM roles, KMS key)
    - Instantiate `StaticHostingCdkStack` (no dependencies)
    - Add explicit `computeStack.addDependency(networkingStack)` and `computeStack.addDependency(securityStack)`
    - Preserve existing CDK context parameter reading (`environment`, `accountId`, `region`, `imageTag`, `domainName`, `certificateArn`)
    - Apply `Project`, `Environment`, `Component` tags to each stack
    - Retain stack names: `clearfin-{env}-networking`, `clearfin-{env}-security`, `clearfin-{env}-compute`, `clearfin-{env}-static-hosting`
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 9.4, 10.1, 10.4_

  - [x] 7.2 Remove or deprecate the placeholder `ClearFinCdkStack` in `packages/infra/src/cdk/cdk-stack.ts`
    - Remove the placeholder stack class since real stacks replace it
    - Update any remaining imports that reference `ClearFinCdkStack`
    - _Requirements: 10.1, 10.2_

  - [x] 7.3 Write integration test for full app synthesis
    - Create or update a test that instantiates all four stacks via `main.ts` logic and calls `app.synth()`
    - Assert all four CloudFormation templates are produced without errors
    - Assert cross-stack references are present (exports/imports)
    - Assert stack dependency ordering (Compute depends on Networking and Security)
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 9.1, 9.3_

- [x] 8. Final checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- No property-based tests — this is declarative IaC tested with CDK assertions and snapshots
- Config builder interfaces and function signatures remain unchanged (Requirement 10.2)
- All CDK stacks consume config builder output as the single source of truth (Requirement 9.2)
