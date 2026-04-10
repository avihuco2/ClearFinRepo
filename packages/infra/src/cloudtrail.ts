// @clearfin/infra — CloudTrail configuration for audit logging
// Validates: Requirements 6.4, 6.5

export interface EventSelectorConfig {
  readWriteType: 'All' | 'ReadOnly' | 'WriteOnly';
  includeManagementEvents: boolean;
  dataResources: Array<{
    type: string;
    values: string[];
  }>;
}

export interface CloudTrailConfig {
  name: string;
  isMultiRegion: boolean;
  enableLogFileValidation: boolean;
  s3BucketName: string;
  s3KeyPrefix: string;
  kmsKeyAlias: string;
  eventSelectors: EventSelectorConfig[];
  insightSelectors: Array<{ insightType: string }>;
  monitoredApiCalls: string[];
  alertRules: Array<{
    name: string;
    description: string;
    eventPattern: {
      source: string[];
      detailType: string[];
      detail: Record<string, unknown>;
    };
    targetSnsTopicName: string;
  }>;
  tags: Record<string, string>;
}

export function buildCloudTrailConfig(env: string, accountId: string, region: string): CloudTrailConfig {
  return {
    name: `clearfin-${env}-audit-trail`,
    isMultiRegion: false,
    enableLogFileValidation: true,
    s3BucketName: `clearfin-${env}-cloudtrail-logs`,
    s3KeyPrefix: `clearfin/${env}`,
    kmsKeyAlias: `clearfin-${env}-secrets-key`,
    eventSelectors: [
      {
        readWriteType: 'All' as const,
        includeManagementEvents: true,
        dataResources: [
          {
            type: 'AWS::SecretsManager::Secret',
            values: [`arn:aws:secretsmanager:${region}:${accountId}:secret:/clearfin/${env}/*`],
          },
        ],
      },
    ],
    insightSelectors: [
      { insightType: 'ApiCallRateInsight' },
      { insightType: 'ApiErrorRateInsight' },
    ],
    // Req 6.4: Monitor IAM, STS, and Secrets Manager policy modifications
    monitoredApiCalls: [
      'iam:PutRolePolicy',
      'iam:AttachRolePolicy',
      'iam:DetachRolePolicy',
      'iam:DeleteRolePolicy',
      'iam:UpdateAssumeRolePolicy',
      'sts:AssumeRole',
      'secretsmanager:PutResourcePolicy',
      'secretsmanager:DeleteResourcePolicy',
      'secretsmanager:CreateSecret',
      'secretsmanager:DeleteSecret',
      'secretsmanager:UpdateSecret',
    ],
    // Req 6.4: Generate security audit event within 60 seconds
    alertRules: [
      {
        name: `clearfin-${env}-iam-policy-change`,
        description: 'Alert on IAM policy modifications',
        eventPattern: {
          source: ['aws.iam'],
          detailType: ['AWS API Call via CloudTrail'],
          detail: {
            eventSource: ['iam.amazonaws.com'],
            eventName: [
              'PutRolePolicy',
              'AttachRolePolicy',
              'DetachRolePolicy',
              'DeleteRolePolicy',
              'UpdateAssumeRolePolicy',
            ],
          },
        },
        targetSnsTopicName: `clearfin-${env}-security-alerts`,
      },
      {
        name: `clearfin-${env}-sts-trust-change`,
        description: 'Alert on STS trust relationship modifications',
        eventPattern: {
          source: ['aws.sts'],
          detailType: ['AWS API Call via CloudTrail'],
          detail: {
            eventSource: ['sts.amazonaws.com'],
          },
        },
        targetSnsTopicName: `clearfin-${env}-security-alerts`,
      },
      {
        name: `clearfin-${env}-secrets-policy-change`,
        description: 'Alert on Secrets Manager resource policy modifications',
        eventPattern: {
          source: ['aws.secretsmanager'],
          detailType: ['AWS API Call via CloudTrail'],
          detail: {
            eventSource: ['secretsmanager.amazonaws.com'],
            eventName: [
              'PutResourcePolicy',
              'DeleteResourcePolicy',
            ],
          },
        },
        targetSnsTopicName: `clearfin-${env}-security-alerts`,
      },
    ],
    tags: {
      Project: 'ClearFin',
      Environment: env,
      Component: 'audit',
    },
  };
}
