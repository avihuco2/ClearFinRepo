# Requirements Document

## Introduction

ClearFin Secure Foundation currently has config builder functions in `packages/infra` that return pure data structures describing AWS infrastructure (VPC, ECS, ECR, ALB, CloudFront, IAM, CloudTrail). Placeholder CDK stacks exist that synthesize and deploy SSM parameters but do not create real AWS resources. This feature converts those config-based definitions into real, deployable AWS CDK constructs so that `cdk deploy` provisions actual infrastructure in `il-central-1` (Tel Aviv). Each CDK construct class consumes the output of its corresponding config builder and creates the matching AWS resources, preserving the existing config-first architecture.

## Glossary

- **Config_Builder**: A pure function in `packages/infra/src` (e.g., `buildVpcConfig`, `buildEcsClusterConfig`) that returns a typed data structure describing an AWS resource configuration.
- **CDK_Construct**: An AWS CDK L2 or L3 construct class that creates real AWS resources from a Config_Builder output during `cdk synth` and `cdk deploy`.
- **Networking_Stack**: The CDK stack responsible for VPC, subnets, NAT Gateways, and VPC PrivateLink endpoints.
- **Compute_Stack**: The CDK stack responsible for ECS Fargate cluster, ECR repositories, ALB, target groups, and Fargate services.
- **Security_Stack**: The CDK stack responsible for KMS keys, IAM roles, and CloudTrail audit logging.
- **Static_Hosting_Stack**: The CDK stack responsible for the S3 bucket and CloudFront distribution serving the Login Page SPA.
- **VPC_Endpoint**: An AWS PrivateLink interface endpoint or S3 gateway endpoint that keeps AWS service traffic off the public internet.
- **CDK_App**: The entry point (`packages/infra/src/cdk/main.ts`) that instantiates all four stacks and calls `app.synth()`.
- **Stack_Output**: A `cdk.CfnOutput` value exported from one stack for consumption by a dependent stack (e.g., VPC ID from Networking_Stack used by Compute_Stack).

## Requirements

### Requirement 1: VPC and Networking Construct

**User Story:** As a platform operator, I want the Networking_Stack to create a real VPC with subnets, NAT Gateways, and VPC PrivateLink endpoints, so that all services run in an isolated network with private AWS service access.

#### Acceptance Criteria

1. WHEN the Networking_Stack is synthesized, THE CDK_Construct SHALL create a VPC with the CIDR block, DNS support, and DNS hostnames settings defined by `buildVpcConfig`.
2. WHEN the Networking_Stack is synthesized, THE CDK_Construct SHALL create public and private subnets across `il-central-1a` and `il-central-1b` with the CIDR blocks defined by `buildVpcConfig`.
3. WHEN the Networking_Stack is synthesized, THE CDK_Construct SHALL create one NAT Gateway per availability zone in the public subnets, each with an Elastic IP allocation.
4. WHEN the Networking_Stack is synthesized, THE CDK_Construct SHALL create interface VPC endpoints for ECR API, ECR Docker, STS, Secrets Manager, KMS, CloudWatch Logs, and CloudWatch Monitoring with private DNS enabled, placed in the private subnets.
5. WHEN the Networking_Stack is synthesized, THE CDK_Construct SHALL create a gateway VPC endpoint for S3 associated with all route tables.
6. THE Networking_Stack SHALL export the VPC ID, public subnet IDs, and private subnet IDs as Stack_Outputs for consumption by dependent stacks.
7. THE CDK_Construct SHALL apply the tags defined in the `VpcConfig` to all networking resources.

### Requirement 2: ECR Repository Construct

**User Story:** As a platform operator, I want the Compute_Stack to create ECR repositories with immutable tags and scan-on-push, so that container images are securely stored and versioned.

#### Acceptance Criteria

1. WHEN the Compute_Stack is synthesized, THE CDK_Construct SHALL create ECR repositories for `clearfin/auth-service`, `clearfin/sts-broker`, and `clearfin/secrets-hierarchy-manager` with immutable image tags as defined by `buildEcrRepositoryConfigs`.
2. THE CDK_Construct SHALL enable scan-on-push for each ECR repository.
3. THE CDK_Construct SHALL configure KMS encryption for each ECR repository using the KMS key alias defined in the `EcrRepositoryConfig`.
4. WHEN the Compute_Stack is synthesized, THE CDK_Construct SHALL apply lifecycle rules that retain the last 10 tagged images and expire untagged images after 7 days as defined by `buildEcrRepositoryConfigs`.
5. THE CDK_Construct SHALL apply the tags defined in each `EcrRepositoryConfig` to the corresponding ECR repository.

### Requirement 3: ECS Fargate Cluster and Services Construct

**User Story:** As a platform operator, I want the Compute_Stack to create an ECS Fargate cluster with three services, so that auth-service, sts-broker, and secrets-hierarchy-manager run as containers in private subnets.

#### Acceptance Criteria

1. WHEN the Compute_Stack is synthesized, THE CDK_Construct SHALL create an ECS Fargate cluster with Container Insights enabled as defined by `buildEcsClusterConfig`.
2. WHEN the Compute_Stack is synthesized, THE CDK_Construct SHALL create a Fargate task definition for each service (auth-service, sts-broker, secrets-hierarchy-manager) with the CPU, memory, container port, and non-root user settings defined in the `EcsClusterConfig`.
3. WHEN the Compute_Stack is synthesized, THE CDK_Construct SHALL create a Fargate service for each task definition, deployed in private subnets with no public IP assignment and the desired count defined in the `EcsClusterConfig`.
4. THE CDK_Construct SHALL reference the ECR repository for each service's container image using the image tag provided in the `CdkStackContext`.
5. THE CDK_Construct SHALL assign the task execution role and task role defined in the `TaskDefinitionConfig` to each Fargate task definition.
6. THE CDK_Construct SHALL configure a health check for each container using the health check path defined in the `TaskDefinitionConfig`.
7. THE CDK_Construct SHALL apply the tags defined in the `EcsClusterConfig` to the cluster and all service resources.

### Requirement 4: Application Load Balancer Construct

**User Story:** As a platform operator, I want the Compute_Stack to create an ALB with TLS termination and health checks, so that HTTPS traffic is routed to the ECS services securely.

#### Acceptance Criteria

1. WHEN the Compute_Stack is synthesized, THE CDK_Construct SHALL create an internet-facing Application Load Balancer in the public subnets as defined by `buildAlbConfig`.
2. WHEN the Compute_Stack is synthesized, THE CDK_Construct SHALL create an HTTPS listener on port 443 with the TLS policy `ELBSecurityPolicy-TLS13-1-2-2021-06` and the ACM certificate ARN provided in the `CdkStackContext`.
3. WHEN the Compute_Stack is synthesized, THE CDK_Construct SHALL create an HTTP listener on port 80 that redirects all traffic to HTTPS with a 301 status code.
4. WHEN the Compute_Stack is synthesized, THE CDK_Construct SHALL create target groups for auth-service (port 3000), sts-broker (port 3001), and secrets-hierarchy-manager (port 3002) with the health check settings defined in the `AlbConfig`.
5. THE CDK_Construct SHALL register each Fargate service with its corresponding ALB target group.
6. THE CDK_Construct SHALL create a security group for the ALB that allows inbound traffic on ports 443 and 80 from `0.0.0.0/0`.
7. THE CDK_Construct SHALL apply the tags defined in the `AlbConfig` to the ALB and target group resources.

### Requirement 5: IAM Roles and KMS Keys Construct

**User Story:** As a platform operator, I want the Security_Stack to create IAM roles and KMS keys, so that ECS tasks have least-privilege permissions and all data is encrypted with customer-managed keys.

#### Acceptance Criteria

1. WHEN the Security_Stack is synthesized, THE CDK_Construct SHALL create a KMS key with automatic rotation enabled and the alias, description, and key policy defined by `buildIamConfig`.
2. WHEN the Security_Stack is synthesized, THE CDK_Construct SHALL create task execution roles for each service (auth-service, sts-broker, secrets-hierarchy-manager) with the trust policy, managed policies, and inline policies defined in the `IamConfig`.
3. WHEN the Security_Stack is synthesized, THE CDK_Construct SHALL create task roles for each service with the trust policy and inline policies (including KMS decrypt permissions) defined in the `IamConfig`.
4. WHEN the Security_Stack is synthesized, THE CDK_Construct SHALL create the STS base role with the trust policy that allows assumption only by the sts-broker task role, as defined in the `IamConfig`.
5. THE Security_Stack SHALL export the KMS key ARN and IAM role ARNs as Stack_Outputs for consumption by the Compute_Stack.
6. THE CDK_Construct SHALL apply the tags defined in each `IamRoleConfig` and `KmsKeyConfig` to the corresponding resources.

### Requirement 6: CloudTrail Audit Logging Construct

**User Story:** As a security auditor, I want the Security_Stack to create a CloudTrail trail with event selectors and alert rules, so that all security-sensitive API calls are logged and monitored.

#### Acceptance Criteria

1. WHEN the Security_Stack is synthesized, THE CDK_Construct SHALL create a CloudTrail trail with log file validation enabled and the S3 bucket, key prefix, and KMS encryption defined by `buildCloudTrailConfig`.
2. WHEN the Security_Stack is synthesized, THE CDK_Construct SHALL create an S3 bucket for CloudTrail logs with server-side encryption, versioning enabled, and a bucket policy that allows CloudTrail to write logs.
3. WHEN the Security_Stack is synthesized, THE CDK_Construct SHALL configure event selectors that capture management events and Secrets Manager data events as defined in the `CloudTrailConfig`.
4. WHEN the Security_Stack is synthesized, THE CDK_Construct SHALL create EventBridge rules for IAM policy changes, STS trust changes, and Secrets Manager policy changes as defined in the `alertRules` of the `CloudTrailConfig`.
5. WHEN the Security_Stack is synthesized, THE CDK_Construct SHALL create an SNS topic for security alerts and subscribe the EventBridge rules to the topic.
6. THE CDK_Construct SHALL apply the tags defined in the `CloudTrailConfig` to the trail and related resources.

### Requirement 7: Static Hosting Construct (S3 + CloudFront)

**User Story:** As a platform operator, I want the Static_Hosting_Stack to create an S3 bucket and CloudFront distribution, so that the Login Page SPA is served securely over HTTPS with proper security headers.

#### Acceptance Criteria

1. WHEN the Static_Hosting_Stack is synthesized, THE CDK_Construct SHALL create an S3 bucket with all public access blocked, AES-256 encryption, and versioning enabled as defined by `buildCloudFrontConfig`.
2. WHEN the Static_Hosting_Stack is synthesized, THE CDK_Construct SHALL create a CloudFront distribution with Origin Access Control (OAC) using SigV4 signing to access the S3 bucket.
3. WHEN the Static_Hosting_Stack is synthesized, THE CDK_Construct SHALL configure the CloudFront distribution with `redirect-to-https` viewer protocol policy, HTTP/2 and HTTP/3 support, and `index.html` as the default root object.
4. WHEN the Static_Hosting_Stack is synthesized, THE CDK_Construct SHALL create a response headers policy with Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options (DENY), X-XSS-Protection, and Referrer-Policy headers as defined in the `CloudFrontConfig`.
5. WHEN the Static_Hosting_Stack is synthesized, THE CDK_Construct SHALL configure custom error responses that return `/index.html` with HTTP 200 for 403 and 404 errors (SPA routing).
6. THE CDK_Construct SHALL apply the tags defined in the `CloudFrontConfig` to the S3 bucket and CloudFront distribution.

### Requirement 8: Stack Orchestration and Cross-Stack References

**User Story:** As a platform operator, I want the CDK_App to orchestrate all four stacks with proper dependency ordering, so that `cdk deploy --all` provisions the complete infrastructure in the correct sequence.

#### Acceptance Criteria

1. THE CDK_App SHALL instantiate the Networking_Stack, Security_Stack, Compute_Stack, and Static_Hosting_Stack with the environment, account ID, region, image tag, domain name, and certificate ARN from CDK context.
2. THE CDK_App SHALL establish a dependency from Compute_Stack to both Networking_Stack and Security_Stack, so that VPC and IAM resources are created before ECS services.
3. THE Compute_Stack SHALL consume the VPC, subnet, and security group references from the Networking_Stack via cross-stack references or Stack_Outputs.
4. THE Compute_Stack SHALL consume the IAM role and KMS key references from the Security_Stack via cross-stack references or Stack_Outputs.
5. THE CDK_App SHALL apply the `Project`, `Environment`, and `Component` tags to each stack as defined by the existing stack naming convention.

### Requirement 9: CDK Synthesis Validation

**User Story:** As a developer, I want `cdk synth` to produce valid CloudFormation templates for all four stacks, so that I can review infrastructure changes before deployment.

#### Acceptance Criteria

1. WHEN `cdk synth` is executed, THE CDK_App SHALL produce a valid CloudFormation template for each of the four stacks without errors.
2. WHEN `cdk synth` is executed, THE CDK_App SHALL consume the config builder outputs without modification, using the data structures as the single source of truth for resource parameters.
3. WHEN a config builder output changes, THE CDK_App SHALL reflect the change in the synthesized CloudFormation template without requiring changes to the CDK_Construct code.
4. THE CDK_App SHALL maintain backward compatibility with the existing CI/CD pipeline stack names (`clearfin-{env}-networking`, `clearfin-{env}-security`, `clearfin-{env}-compute`, `clearfin-{env}-static-hosting`).

### Requirement 10: Existing Test and Pipeline Compatibility

**User Story:** As a developer, I want the CDK construct changes to preserve existing test suites and the CI/CD pipeline, so that the migration from placeholder stacks to real constructs does not break the deployment workflow.

#### Acceptance Criteria

1. WHEN the CDK constructs are implemented, THE CDK_App SHALL continue to use the same entry point (`packages/infra/src/cdk/main.ts`) and CDK context parameters as the existing placeholder stacks.
2. THE CDK_Construct implementation SHALL preserve the existing config builder interfaces and function signatures without modification.
3. WHEN `cdk diff` is executed against the deployed placeholder stacks, THE CDK_App SHALL show the addition of real AWS resources and the removal of placeholder SSM parameters.
4. THE CDK_App SHALL continue to support the `--context` flags used by the GitHub Actions deployment workflow (`environment`, `accountId`, `region`, `imageTag`, `domainName`, `certificateArn`).
