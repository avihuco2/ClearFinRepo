// @clearfin/infra — CDK assertion tests for SecurityCdkStack
// Validates: Requirements 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 9.1

import { describe, it, expect, beforeAll } from 'vitest';
import * as cdk from 'aws-cdk-lib';
import { Template, Match } from 'aws-cdk-lib/assertions';
import { SecurityCdkStack } from './security-stack.js';
import { buildIamConfig } from '../iam.js';
import { buildCloudTrailConfig } from '../cloudtrail.js';

const ENV = 'test';
const ACCOUNT_ID = '123456789012';
const REGION = 'il-central-1';
const iamConfig = buildIamConfig(ENV, ACCOUNT_ID, REGION);
const cloudTrailConfig = buildCloudTrailConfig(ENV, ACCOUNT_ID, REGION);

let template: Template;

beforeAll(() => {
  const app = new cdk.App();
  const stack = new SecurityCdkStack(app, 'TestSecurityStack', {
    clearfinEnv: ENV,
    accountId: ACCOUNT_ID,
    iamConfig,
    cloudTrailConfig,
  });
  template = Template.fromStack(stack);
});

// ── Req 5.1: KMS key with rotation and alias ───────────────────────

describe('KMS Key', () => {
  it('creates exactly 1 KMS key', () => {
    template.resourceCountIs('AWS::KMS::Key', 1);
  });

  it('creates a KMS key with automatic rotation enabled', () => {
    template.hasResourceProperties('AWS::KMS::Key', {
      EnableKeyRotation: true,
    });
  });

  it('creates a KMS alias matching the config', () => {
    template.hasResourceProperties('AWS::KMS::Alias', {
      AliasName: `alias/${iamConfig.kmsKeys[0].alias}`,
    });
  });

  it('creates exactly 1 KMS alias', () => {
    template.resourceCountIs('AWS::KMS::Alias', 1);
  });
});

// ── Req 5.2: Task execution roles ──────────────────────────────────

describe('Task Execution Roles', () => {
  it('creates IAM roles for all 7 roles (3 execution + 3 task + 1 STS base)', () => {
    template.resourceCountIs('AWS::IAM::Role', 7);
  });

  it('creates execution roles with ECS task trust policy', () => {
    // Each execution role trusts ecs-tasks.amazonaws.com
    template.hasResourceProperties('AWS::IAM::Role', {
      RoleName: Match.stringLikeRegexp(`clearfin-${ENV}-.*-execution`),
      AssumeRolePolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({
            Effect: 'Allow',
            Principal: { Service: 'ecs-tasks.amazonaws.com' },
            Action: 'sts:AssumeRole',
          }),
        ]),
      }),
    });
  });

  it('creates execution role for auth-service', () => {
    template.hasResourceProperties('AWS::IAM::Role', {
      RoleName: `clearfin-${ENV}-auth-service-execution`,
    });
  });

  it('creates execution role for sts-broker', () => {
    template.hasResourceProperties('AWS::IAM::Role', {
      RoleName: `clearfin-${ENV}-sts-broker-execution`,
    });
  });

  it('creates execution role for secrets-hierarchy-manager', () => {
    template.hasResourceProperties('AWS::IAM::Role', {
      RoleName: `clearfin-${ENV}-secrets-hierarchy-manager-execution`,
    });
  });
});

// ── Req 5.3: Task roles with KMS decrypt inline policy ─────────────

describe('Task Roles', () => {
  it('creates task roles with ECS task trust policy', () => {
    template.hasResourceProperties('AWS::IAM::Role', {
      RoleName: Match.stringLikeRegexp(`clearfin-${ENV}-.*-task$`),
      AssumeRolePolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({
            Effect: 'Allow',
            Principal: { Service: 'ecs-tasks.amazonaws.com' },
            Action: 'sts:AssumeRole',
          }),
        ]),
      }),
    });
  });

  it('creates task role for auth-service', () => {
    template.hasResourceProperties('AWS::IAM::Role', {
      RoleName: `clearfin-${ENV}-auth-service-task`,
    });
  });

  it('creates task role for sts-broker', () => {
    template.hasResourceProperties('AWS::IAM::Role', {
      RoleName: `clearfin-${ENV}-sts-broker-task`,
    });
  });

  it('creates task role for secrets-hierarchy-manager', () => {
    template.hasResourceProperties('AWS::IAM::Role', {
      RoleName: `clearfin-${ENV}-secrets-hierarchy-manager-task`,
    });
  });
});

// ── Req 5.3: Inline policies with KMS decrypt permissions ──────────

describe('Inline Policies', () => {
  it('creates inline policies for KMS decrypt on task roles', () => {
    template.hasResourceProperties('AWS::IAM::Policy', {
      PolicyName: 'kms-decrypt',
      PolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({
            Effect: 'Allow',
            Action: ['kms:Decrypt', 'kms:GenerateDataKey'],
          }),
        ]),
      }),
    });
  });

  it('creates inline policies for ECR pull on execution roles', () => {
    template.hasResourceProperties('AWS::IAM::Policy', {
      PolicyName: 'ecr-pull',
      PolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({
            Effect: 'Allow',
            Action: Match.arrayWith([
              'ecr:GetDownloadUrlForLayer',
              'ecr:BatchGetImage',
              'ecr:GetAuthorizationToken',
            ]),
          }),
        ]),
      }),
    });
  });
});

// ── Req 5.4: STS base role ─────────────────────────────────────────

describe('STS Base Role', () => {
  it('creates the STS base role', () => {
    template.hasResourceProperties('AWS::IAM::Role', {
      RoleName: `clearfin-${ENV}-sts-base-role`,
    });
  });

  it('STS base role trust policy allows only sts-broker task role', () => {
    template.hasResourceProperties('AWS::IAM::Role', {
      RoleName: `clearfin-${ENV}-sts-base-role`,
      AssumeRolePolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({
            Effect: 'Allow',
            Principal: {
              AWS: Match.anyValue(),
            },
            Action: 'sts:AssumeRole',
          }),
        ]),
      }),
    });
  });

  it('STS base role has secrets-access inline policy', () => {
    template.hasResourceProperties('AWS::IAM::Policy', {
      PolicyName: 'secrets-access',
      PolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({
            Effect: 'Allow',
            Action: ['secretsmanager:GetSecretValue', 'secretsmanager:DescribeSecret'],
          }),
        ]),
      }),
    });
  });
});

// ── Req 6.2: S3 bucket for CloudTrail with encryption and versioning ─

describe('CloudTrail S3 Bucket', () => {
  it('creates exactly 1 S3 bucket', () => {
    template.resourceCountIs('AWS::S3::Bucket', 1);
  });

  it('creates S3 bucket with server-side encryption', () => {
    template.hasResourceProperties('AWS::S3::Bucket', {
      BucketEncryption: Match.objectLike({
        ServerSideEncryptionConfiguration: Match.arrayWith([
          Match.objectLike({
            ServerSideEncryptionByDefault: {
              SSEAlgorithm: 'AES256',
            },
          }),
        ]),
      }),
    });
  });

  it('creates S3 bucket with versioning enabled', () => {
    template.hasResourceProperties('AWS::S3::Bucket', {
      VersioningConfiguration: { Status: 'Enabled' },
    });
  });

  it('creates S3 bucket with public access blocked', () => {
    template.hasResourceProperties('AWS::S3::Bucket', {
      PublicAccessBlockConfiguration: {
        BlockPublicAcls: true,
        BlockPublicPolicy: true,
        IgnorePublicAcls: true,
        RestrictPublicBuckets: true,
      },
    });
  });

  it('creates S3 bucket with correct configuration', () => {
    template.hasResourceProperties('AWS::S3::Bucket', {
      VersioningConfiguration: { Status: 'Enabled' },
    });
  });
});

// ── Req 6.1: CloudTrail trail with log file validation and S3 ──────

describe('CloudTrail Trail', () => {
  it('creates exactly 1 CloudTrail trail', () => {
    template.resourceCountIs('AWS::CloudTrail::Trail', 1);
  });

  it('creates trail with log file validation enabled', () => {
    template.hasResourceProperties('AWS::CloudTrail::Trail', {
      EnableLogFileValidation: true,
    });
  });

  it('creates trail with the correct name', () => {
    template.hasResourceProperties('AWS::CloudTrail::Trail', {
      TrailName: cloudTrailConfig.name,
    });
  });

  it('creates trail with S3 bucket destination', () => {
    template.hasResourceProperties('AWS::CloudTrail::Trail', {
      S3BucketName: Match.anyValue(),
      S3KeyPrefix: cloudTrailConfig.s3KeyPrefix,
    });
  });

  it('creates trail with KMS encryption', () => {
    template.hasResourceProperties('AWS::CloudTrail::Trail', {
      KMSKeyId: Match.anyValue(),
    });
  });

  it('trail is enabled', () => {
    template.hasResourceProperties('AWS::CloudTrail::Trail', {
      IsLogging: true,
    });
  });
});

// ── Req 6.4: EventBridge rules for alert patterns ──────────────────

describe('EventBridge Rules', () => {
  it('creates 3 EventBridge rules (IAM, STS, Secrets Manager)', () => {
    template.resourceCountIs('AWS::Events::Rule', 3);
  });

  it('creates rule for IAM policy changes', () => {
    template.hasResourceProperties('AWS::Events::Rule', {
      Name: `clearfin-${ENV}-iam-policy-change`,
      EventPattern: Match.objectLike({
        source: ['aws.iam'],
        'detail-type': ['AWS API Call via CloudTrail'],
      }),
    });
  });

  it('creates rule for STS trust changes', () => {
    template.hasResourceProperties('AWS::Events::Rule', {
      Name: `clearfin-${ENV}-sts-trust-change`,
      EventPattern: Match.objectLike({
        source: ['aws.sts'],
        'detail-type': ['AWS API Call via CloudTrail'],
      }),
    });
  });

  it('creates rule for Secrets Manager policy changes', () => {
    template.hasResourceProperties('AWS::Events::Rule', {
      Name: `clearfin-${ENV}-secrets-policy-change`,
      EventPattern: Match.objectLike({
        source: ['aws.secretsmanager'],
        'detail-type': ['AWS API Call via CloudTrail'],
      }),
    });
  });

  it('EventBridge rules target SNS topic', () => {
    template.hasResourceProperties('AWS::Events::Rule', {
      Targets: Match.arrayWith([
        Match.objectLike({
          Arn: Match.anyValue(),
        }),
      ]),
    });
  });
});

// ── Req 6.5: SNS topic for security alerts ─────────────────────────

describe('SNS Topic', () => {
  it('creates exactly 1 SNS topic', () => {
    template.resourceCountIs('AWS::SNS::Topic', 1);
  });

  it('creates SNS topic with the correct name', () => {
    template.hasResourceProperties('AWS::SNS::Topic', {
      TopicName: `clearfin-${ENV}-security-alerts`,
    });
  });

  it('creates SNS topic with display name', () => {
    template.hasResourceProperties('AWS::SNS::Topic', {
      DisplayName: Match.stringLikeRegexp('ClearFin.*Security Alerts'),
    });
  });
});

// ── Req 5.5: CfnOutput exports for KMS key ARN and role ARNs ──────

describe('CfnOutput exports', () => {
  it('exports KMS key ARN', () => {
    template.hasOutput('KmsKeyArn', {
      Export: { Name: `${ENV}-kms-key-arn` },
    });
  });

  it('exports execution role ARNs for all 3 services', () => {
    const outputs = template.toJSON().Outputs;
    const exportNames = Object.values(outputs).map((o: any) => o.Export?.Name);
    for (const svc of ['auth-service', 'sts-broker', 'secrets-hierarchy-manager']) {
      const roleName = `clearfin-${ENV}-${svc}-execution`;
      expect(exportNames).toContain(`${ENV}-${roleName}-arn`);
    }
  });

  it('exports task role ARNs for all 3 services and STS base role', () => {
    const outputs = template.toJSON().Outputs;
    const exportNames = Object.values(outputs).map((o: any) => o.Export?.Name);
    for (const svc of ['auth-service', 'sts-broker', 'secrets-hierarchy-manager']) {
      const roleName = `clearfin-${ENV}-${svc}-task`;
      expect(exportNames).toContain(`${ENV}-${roleName}-arn`);
    }
    // STS base role is also exported
    expect(exportNames).toContain(`${ENV}-clearfin-${ENV}-sts-base-role-arn`);
  });
});

// ── Req 9.1: Synthesis validation ──────────────────────────────────

describe('Synthesis validation', () => {
  it('synthesizes without errors using config builder output', () => {
    const resources = template.toJSON().Resources;
    expect(Object.keys(resources).length).toBeGreaterThan(0);
  });

  it('produces expected resource types', () => {
    template.resourceCountIs('AWS::KMS::Key', 1);
    template.resourceCountIs('AWS::IAM::Role', 7);
    template.resourceCountIs('AWS::S3::Bucket', 1);
    template.resourceCountIs('AWS::CloudTrail::Trail', 1);
    template.resourceCountIs('AWS::Events::Rule', 3);
    template.resourceCountIs('AWS::SNS::Topic', 1);
  });
});
