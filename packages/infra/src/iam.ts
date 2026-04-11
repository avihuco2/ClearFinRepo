// @clearfin/infra — KMS keys, IAM roles, and trust policies
// Validates: Requirements 2.2, 4.3, 4.8

export interface KmsKeyConfig {
  alias: string;
  description: string;
  keySpec: 'SYMMETRIC_DEFAULT';
  keyUsage: 'ENCRYPT_DECRYPT';
  enableKeyRotation: boolean;
  policy: {
    allowAdminArns: string[];
    allowUsageArns: string[];
  };
  tags: Record<string, string>;
}

export interface TrustPolicyStatement {
  Effect: 'Allow';
  Principal: { Service: string } | { AWS: string };
  Action: string;
  Condition?: Record<string, Record<string, string>>;
}

export interface IamRoleConfig {
  name: string;
  description: string;
  trustPolicy: {
    Version: '2012-10-17';
    Statement: TrustPolicyStatement[];
  };
  managedPolicies: string[];
  inlinePolicies: Array<{
    name: string;
    statements: Array<{
      Effect: 'Allow' | 'Deny';
      Action: string[];
      Resource: string[];
      Condition?: Record<string, Record<string, string>>;
    }>;
  }>;
  tags: Record<string, string>;
}

export interface IamConfig {
  kmsKeys: KmsKeyConfig[];
  roles: IamRoleConfig[];
}

const SERVICES = ['auth-service', 'sts-broker', 'secrets-hierarchy-manager'] as const;

export function buildIamConfig(env: string, accountId: string, region: string): IamConfig {
  // Req 2.2, 4.3: Per-environment KMS key for secrets and session data
  const kmsKeys: KmsKeyConfig[] = [
    {
      alias: `clearfin-${env}-secrets-key`,
      description: `ClearFin ${env} encryption key for Secrets Manager and session data`,
      keySpec: 'SYMMETRIC_DEFAULT' as const,
      keyUsage: 'ENCRYPT_DECRYPT' as const,
      enableKeyRotation: true,
      policy: {
        allowAdminArns: [`arn:aws:iam::${accountId}:role/clearfin-${env}-admin`],
        allowUsageArns: SERVICES.map(
          (svc) => `arn:aws:iam::${accountId}:role/clearfin-${env}-${svc}-task`
        ),
      },
      tags: {
        Project: 'ClearFin',
        Environment: env,
        Component: 'encryption',
      },
    },
  ];

  const taskExecutionRoles: IamRoleConfig[] = SERVICES.map((svc) => ({
    name: `clearfin-${env}-${svc}-execution`,
    description: `ECS task execution role for ${svc} — pulls images from ECR`,
    trustPolicy: {
      Version: '2012-10-17' as const,
      Statement: [
        {
          Effect: 'Allow' as const,
          Principal: { Service: 'ecs-tasks.amazonaws.com' },
          Action: 'sts:AssumeRole',
        },
      ],
    },
    managedPolicies: [
      'arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy',
    ],
    inlinePolicies: [
      {
        name: 'ecr-pull',
        statements: [
          {
            Effect: 'Allow' as const,
            Action: [
              'ecr:GetDownloadUrlForLayer',
              'ecr:BatchGetImage',
              'ecr:GetAuthorizationToken',
            ],
            Resource: [`arn:aws:ecr:${region}:${accountId}:repository/clearfin/${svc}`],
          },
        ],
      },
    ],
    tags: {
      Project: 'ClearFin',
      Environment: env,
      Component: 'iam',
      Service: svc,
    },
  }));

  const taskRoles: IamRoleConfig[] = SERVICES.map((svc) => {
    const inlinePolicies: IamRoleConfig['inlinePolicies'] = [
      {
        name: 'kms-decrypt',
        statements: [
          {
            Effect: 'Allow' as const,
            Action: ['kms:Decrypt', 'kms:GenerateDataKey'],
            Resource: [`arn:aws:kms:${region}:${accountId}:alias/clearfin-${env}-secrets-key`],
          },
        ],
      },
    ];

    if (svc === 'auth-service') {
      inlinePolicies.push({
        name: 'secrets-read-google-oauth',
        statements: [
          {
            Effect: 'Allow' as const,
            Action: ['secretsmanager:GetSecretValue'],
            Resource: [
              `arn:aws:secretsmanager:${region}:${accountId}:secret:/clearfin/${env}/_platform/google-oauth-*`,
            ],
          },
        ],
      });
    }

    return {
      name: `clearfin-${env}-${svc}-task`,
      description: `ECS task role for ${svc} — runtime permissions`,
      trustPolicy: {
        Version: '2012-10-17' as const,
        Statement: [
          {
            Effect: 'Allow' as const,
            Principal: { Service: 'ecs-tasks.amazonaws.com' },
            Action: 'sts:AssumeRole',
          },
        ],
      },
      managedPolicies: [],
      inlinePolicies,
      tags: {
        Project: 'ClearFin',
        Environment: env,
        Component: 'iam',
        Service: svc,
      },
    };
  });

  // STS base role for JIT credential assumption (Req 4.8)
  const stsBaseRole: IamRoleConfig = {
    name: `clearfin-${env}-sts-base-role`,
    description: 'Base role assumed by STS_Broker for JIT credential issuance',
    trustPolicy: {
      Version: '2012-10-17' as const,
      Statement: [
        {
          Effect: 'Allow' as const,
          Principal: {
            AWS: `arn:aws:iam::${accountId}:role/clearfin-${env}-sts-broker-task`,
          },
          Action: 'sts:AssumeRole',
        },
      ],
    },
    managedPolicies: [],
    inlinePolicies: [
      {
        name: 'secrets-access',
        statements: [
          {
            Effect: 'Allow' as const,
            Action: [
              'secretsmanager:GetSecretValue',
              'secretsmanager:DescribeSecret',
            ],
            Resource: [
              `arn:aws:secretsmanager:${region}:${accountId}:secret:/clearfin/${env}/*`,
            ],
          },
        ],
      },
    ],
    tags: {
      Project: 'ClearFin',
      Environment: env,
      Component: 'iam',
      Service: 'sts-base',
    },
  };

  return {
    kmsKeys,
    roles: [...taskExecutionRoles, ...taskRoles, stsBaseRole],
  };
}
