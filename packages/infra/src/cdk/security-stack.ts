// @clearfin/infra — SecurityCdkStack: KMS keys, IAM roles, CloudTrail, EventBridge alerts, SNS
// Validates: Requirements 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 6.1, 6.2, 6.3, 6.4, 6.5, 6.6

import * as cdk from 'aws-cdk-lib';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as cloudtrail from 'aws-cdk-lib/aws-cloudtrail';
import * as events from 'aws-cdk-lib/aws-events';
import * as targets from 'aws-cdk-lib/aws-events-targets';
import * as sns from 'aws-cdk-lib/aws-sns';
import { Construct } from 'constructs';
import type { IamConfig, IamRoleConfig } from '../iam.js';
import type { CloudTrailConfig } from '../cloudtrail.js';

export interface SecurityCdkStackProps extends cdk.StackProps {
  clearfinEnv: string;
  accountId: string;
  iamConfig: IamConfig;
  cloudTrailConfig: CloudTrailConfig;
}

export class SecurityCdkStack extends cdk.Stack {
  public readonly kmsKey: kms.Key;
  public readonly taskExecutionRoles: Record<string, iam.Role>;
  public readonly taskRoles: Record<string, iam.Role>;

  constructor(scope: Construct, id: string, props: SecurityCdkStackProps) {
    super(scope, id, props);

    const { clearfinEnv, accountId, iamConfig, cloudTrailConfig } = props;

    // Req 5.6: Apply tags from IamConfig KMS key and CloudTrailConfig
    for (const kmsKeyCfg of iamConfig.kmsKeys) {
      for (const [key, value] of Object.entries(kmsKeyCfg.tags)) {
        cdk.Tags.of(this).add(key, value);
      }
    }
    for (const [key, value] of Object.entries(cloudTrailConfig.tags)) {
      cdk.Tags.of(this).add(key, value);
    }

    // ─── KMS Key ───────────────────────────────────────────────────────
    // Req 5.1: Create KMS key with alias, automatic rotation, key policy
    const kmsKeyCfg = iamConfig.kmsKeys[0];

    this.kmsKey = new kms.Key(this, 'KmsKey', {
      alias: kmsKeyCfg.alias,
      description: kmsKeyCfg.description,
      enableKeyRotation: kmsKeyCfg.enableKeyRotation,
      keySpec: kms.KeySpec.SYMMETRIC_DEFAULT,
      keyUsage: kms.KeyUsage.ENCRYPT_DECRYPT,
    });

    // Key policy: allow account root full key management (admin)
    // The config references a clearfin-{env}-admin role that may not exist yet,
    // so we use the account root as the key administrator instead.
    this.kmsKey.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: 'AllowKeyAdmin',
        effect: iam.Effect.ALLOW,
        principals: [new iam.AccountRootPrincipal()],
        actions: [
          'kms:Create*',
          'kms:Describe*',
          'kms:Enable*',
          'kms:List*',
          'kms:Put*',
          'kms:Update*',
          'kms:Revoke*',
          'kms:Disable*',
          'kms:Get*',
          'kms:Delete*',
          'kms:TagResource',
          'kms:UntagResource',
          'kms:ScheduleKeyDeletion',
          'kms:CancelKeyDeletion',
        ],
        resources: ['*'],
      }),
    );

    // Key policy: allow usage ARNs to encrypt/decrypt
    // Skip adding usage ARN policy statements here — the task roles are created
    // in this same stack and will be granted access after creation below.

    // Apply KMS key tags
    for (const [key, value] of Object.entries(kmsKeyCfg.tags)) {
      cdk.Tags.of(this.kmsKey).add(key, value);
    }

    // ─── IAM Roles ─────────────────────────────────────────────────────
    // Req 5.2, 5.3, 5.4: Create IAM roles from iamConfig.roles
    this.taskExecutionRoles = {};
    this.taskRoles = {};

    for (const roleCfg of iamConfig.roles) {
      const role = this.createIamRole(roleCfg);

      // Apply per-role tags
      for (const [key, value] of Object.entries(roleCfg.tags)) {
        cdk.Tags.of(role).add(key, value);
      }

      // Categorize: execution roles, task roles, or STS base role
      if (roleCfg.name.includes('execution')) {
        this.taskExecutionRoles[roleCfg.name] = role;
      } else if (roleCfg.name.includes('sts-base')) {
        // STS base role — exported but not in taskRoles map
        this.taskRoles[roleCfg.name] = role;
      } else if (roleCfg.name.includes('task')) {
        this.taskRoles[roleCfg.name] = role;
        // Grant KMS decrypt/encrypt access to task roles (same-stack reference)
        this.kmsKey.grant(role, 'kms:Decrypt', 'kms:GenerateDataKey', 'kms:DescribeKey');
      }
    }

    // ─── CloudTrail S3 Bucket ──────────────────────────────────────────
    // Req 6.2: S3 bucket for CloudTrail logs with encryption, versioning, CloudTrail write policy
    const trailBucket = new s3.Bucket(this, 'CloudTrailBucket', {
      bucketName: cloudTrailConfig.s3BucketName,
      encryption: s3.BucketEncryption.S3_MANAGED,
      versioned: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      enforceSSL: true,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // Allow CloudTrail to write logs to the bucket
    trailBucket.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: 'AWSCloudTrailAclCheck',
        effect: iam.Effect.ALLOW,
        principals: [new iam.ServicePrincipal('cloudtrail.amazonaws.com')],
        actions: ['s3:GetBucketAcl'],
        resources: [trailBucket.bucketArn],
      }),
    );

    trailBucket.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: 'AWSCloudTrailWrite',
        effect: iam.Effect.ALLOW,
        principals: [new iam.ServicePrincipal('cloudtrail.amazonaws.com')],
        actions: ['s3:PutObject'],
        resources: [`${trailBucket.bucketArn}/${cloudTrailConfig.s3KeyPrefix}/*`],
        conditions: {
          StringEquals: {
            's3:x-amz-acl': 'bucket-owner-full-control',
          },
        },
      }),
    );

    // ─── CloudTrail Trail ──────────────────────────────────────────────
    // Req 6.1, 6.3: CloudTrail trail with log file validation, S3 destination, KMS encryption
    const trail = new cloudtrail.Trail(this, 'AuditTrail', {
      trailName: cloudTrailConfig.name,
      bucket: trailBucket,
      s3KeyPrefix: cloudTrailConfig.s3KeyPrefix,
      enableFileValidation: cloudTrailConfig.enableLogFileValidation,
      isMultiRegionTrail: cloudTrailConfig.isMultiRegion,
      encryptionKey: this.kmsKey,
      sendToCloudWatchLogs: false,
      includeGlobalServiceEvents: true,
    });

    // Allow CloudTrail to use the KMS key for encryption
    this.kmsKey.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: 'AllowCloudTrailEncrypt',
        effect: iam.Effect.ALLOW,
        principals: [new iam.ServicePrincipal('cloudtrail.amazonaws.com')],
        actions: ['kms:GenerateDataKey*', 'kms:DescribeKey'],
        resources: ['*'],
      }),
    );

    // Req 6.3: Configure event selectors for management events and data events
    for (const selector of cloudTrailConfig.eventSelectors) {
      for (const dataResource of selector.dataResources) {
        trail.addEventSelector(cloudtrail.DataResourceType.S3_OBJECT, dataResource.values, {
          includeManagementEvents: selector.includeManagementEvents,
          readWriteType: selector.readWriteType === 'All'
            ? cloudtrail.ReadWriteType.ALL
            : selector.readWriteType === 'ReadOnly'
              ? cloudtrail.ReadWriteType.READ_ONLY
              : cloudtrail.ReadWriteType.WRITE_ONLY,
        });
      }
    }

    // ─── SNS Topic for Security Alerts ─────────────────────────────────
    // Req 6.5: Create SNS topic for security alerts, reused by all EventBridge rules
    // All alert rules target the same SNS topic name, so create it once
    const snsTopicName = cloudTrailConfig.alertRules.length > 0
      ? cloudTrailConfig.alertRules[0].targetSnsTopicName
      : `clearfin-${clearfinEnv}-security-alerts`;

    const securityAlertsTopic = new sns.Topic(this, 'SecurityAlertsTopic', {
      topicName: snsTopicName,
      displayName: `ClearFin ${clearfinEnv} Security Alerts`,
    });

    // ─── EventBridge Rules ─────────────────────────────────────────────
    // Req 6.4: Create EventBridge rules for IAM policy changes, STS trust changes,
    // Secrets Manager policy changes
    for (const alertRule of cloudTrailConfig.alertRules) {
      const rule = new events.Rule(this, alertRule.name, {
        ruleName: alertRule.name,
        description: alertRule.description,
        eventPattern: {
          source: alertRule.eventPattern.source,
          detailType: alertRule.eventPattern.detailType,
          detail: alertRule.eventPattern.detail,
        },
      });

      rule.addTarget(new targets.SnsTopic(securityAlertsTopic));
    }

    // ─── CfnOutputs ────────────────────────────────────────────────────
    // Req 5.5: Export KMS key ARN and IAM role ARNs
    new cdk.CfnOutput(this, 'KmsKeyArn', {
      value: this.kmsKey.keyArn,
      exportName: `${clearfinEnv}-kms-key-arn`,
    });

    for (const [roleName, role] of Object.entries(this.taskExecutionRoles)) {
      new cdk.CfnOutput(this, `ExecutionRoleArn-${roleName}`, {
        value: role.roleArn,
        exportName: `${clearfinEnv}-${roleName}-arn`,
      });
    }

    for (const [roleName, role] of Object.entries(this.taskRoles)) {
      new cdk.CfnOutput(this, `TaskRoleArn-${roleName}`, {
        value: role.roleArn,
        exportName: `${clearfinEnv}-${roleName}-arn`,
      });
    }
  }

  /**
   * Create an IAM role from an IamRoleConfig, mapping trust policy,
   * managed policies, and inline policies.
   */
  private createIamRole(roleCfg: IamRoleConfig): iam.Role {
    // Build the trust policy principals from the config
    const assumeRolePolicyDocument = new iam.PolicyDocument({
      statements: roleCfg.trustPolicy.Statement.map((stmt) => {
        let principal: iam.IPrincipal;
        if ('Service' in stmt.Principal) {
          principal = new iam.ServicePrincipal(stmt.Principal.Service);
        } else {
          principal = new iam.ArnPrincipal(stmt.Principal.AWS);
        }

        return new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          principals: [principal],
          actions: [stmt.Action],
          conditions: stmt.Condition,
        });
      }),
    });

    const role = new iam.Role(this, roleCfg.name, {
      roleName: roleCfg.name,
      description: roleCfg.description,
      assumedBy: new iam.CompositePrincipal(
        ...assumeRolePolicyDocument.statementCount > 0
          ? roleCfg.trustPolicy.Statement.map((stmt) => {
              if ('Service' in stmt.Principal) {
                return new iam.ServicePrincipal(stmt.Principal.Service);
              }
              return new iam.ArnPrincipal(stmt.Principal.AWS);
            })
          : [new iam.ServicePrincipal('ecs-tasks.amazonaws.com')],
      ),
    });

    // Attach managed policies
    for (const managedPolicyArn of roleCfg.managedPolicies) {
      role.addManagedPolicy(iam.ManagedPolicy.fromManagedPolicyArn(this, `${roleCfg.name}-${managedPolicyArn.split('/').pop()}`, managedPolicyArn));
    }

    // Attach inline policies
    for (const inlinePolicy of roleCfg.inlinePolicies) {
      const policyStatements = inlinePolicy.statements.map(
        (stmt) =>
          new iam.PolicyStatement({
            effect: stmt.Effect === 'Allow' ? iam.Effect.ALLOW : iam.Effect.DENY,
            actions: stmt.Action,
            resources: stmt.Resource,
            conditions: stmt.Condition,
          }),
      );

      role.attachInlinePolicy(
        new iam.Policy(this, `${roleCfg.name}-${inlinePolicy.name}`, {
          policyName: inlinePolicy.name,
          statements: policyStatements,
        }),
      );
    }

    return role;
  }
}
