// @clearfin/infra — ECR repositories with security configuration
// Validates: Requirements 6.1

export interface LifecycleRule {
  description: string;
  tagStatus: 'tagged' | 'untagged';
  countType: 'imageCountMoreThan' | 'sinceImagePushed';
  countNumber: number;
  countUnit?: 'days';
  action: 'expire';
}

export interface EcrRepositoryConfig {
  name: string;
  imageTagMutability: 'IMMUTABLE';
  scanOnPush: boolean;
  encryptionType: 'KMS';
  kmsKeyAlias: string;
  lifecycleRules: LifecycleRule[];
  repositoryPolicy: {
    allowPushRoles: string[];
    allowPullRoles: string[];
  };
  tags: Record<string, string>;
}

const REPOSITORY_NAMES = [
  'clearfin/auth-service',
  'clearfin/sts-broker',
  'clearfin/secrets-hierarchy-manager',
];

export function buildEcrRepositoryConfigs(env: string): EcrRepositoryConfig[] {
  return REPOSITORY_NAMES.map((repoName) => {
    const serviceName = repoName.split('/')[1];
    return {
      name: repoName,
      imageTagMutability: 'IMMUTABLE' as const,
      scanOnPush: true,
      encryptionType: 'KMS' as const,
      kmsKeyAlias: `clearfin-${env}-ecr-key`,
      lifecycleRules: [
        {
          description: 'Retain last 10 tagged images',
          tagStatus: 'tagged' as const,
          countType: 'imageCountMoreThan' as const,
          countNumber: 10,
          action: 'expire' as const,
        },
        {
          description: 'Expire untagged images after 7 days',
          tagStatus: 'untagged' as const,
          countType: 'sinceImagePushed' as const,
          countNumber: 7,
          countUnit: 'days' as const,
          action: 'expire' as const,
        },
      ],
      repositoryPolicy: {
        allowPushRoles: [`clearfin-${env}-cicd-pipeline`],
        allowPullRoles: [`clearfin-${env}-${serviceName}-execution`],
      },
      tags: {
        Project: 'ClearFin',
        Environment: env,
        Component: 'container-registry',
        Service: serviceName,
      },
    };
  });
}
