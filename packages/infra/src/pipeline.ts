// @clearfin/infra — Sentinel_Gate CI/CD pipeline integration
// Validates: Requirements 5.1, 5.2, 5.3

export interface PipelineStageConfig {
  name: string;
  order: number;
  actions: PipelineActionConfig[];
}

export interface PipelineActionConfig {
  name: string;
  type: 'source' | 'build' | 'approval' | 'deploy';
  provider: string;
  configuration: Record<string, string>;
}

export interface ArtifactValidationConfig {
  requiredComponents: string[];
  hashAlgorithm: 'SHA-256';
}

export interface SentinelGateStageConfig {
  name: string;
  artifactValidation: ArtifactValidationConfig;
  approvalConfig: {
    approverIdentity: string;
    timeoutMinutes: number;
    onTimeout: 'halt';
    onRejection: 'halt';
  };
  auditLogConfig: {
    logGroupName: string;
    retentionDays: number;
    immutable: boolean;
  };
}

export interface PipelineConfig {
  name: string;
  stages: PipelineStageConfig[];
  sentinelGate: SentinelGateStageConfig;
  ecrRepositories: string[];
  s3DeployBucket: string;
  tags: Record<string, string>;
}

export function buildPipelineConfig(env: string): PipelineConfig {
  const stages: PipelineStageConfig[] = [
    {
      name: 'Source',
      order: 1,
      actions: [
        {
          name: 'SourceAction',
          type: 'source' as const,
          provider: 'CodeCommit',
          configuration: {
            RepositoryName: 'clearfin-secure-foundation',
            BranchName: env === 'prod' ? 'main' : env,
          },
        },
      ],
    },
    {
      name: 'Build',
      order: 2,
      actions: [
        {
          name: 'BuildAndTest',
          type: 'build' as const,
          provider: 'CodeBuild',
          configuration: {
            ProjectName: `clearfin-${env}-build`,
          },
        },
        {
          name: 'ContainerBuild',
          type: 'build' as const,
          provider: 'CodeBuild',
          configuration: {
            ProjectName: `clearfin-${env}-docker-build`,
          },
        },
      ],
    },
    {
      name: 'ArtifactValidation',
      order: 3,
      actions: [
        {
          name: 'ValidateArtifact',
          type: 'build' as const,
          provider: 'CodeBuild',
          configuration: {
            ProjectName: `clearfin-${env}-artifact-validation`,
          },
        },
      ],
    },
    {
      // Req 5.1: Block promotion until sentinel approval
      name: 'SentinelApproval',
      order: 4,
      actions: [
        {
          name: 'SentinelGateApproval',
          type: 'approval' as const,
          provider: 'Manual',
          configuration: {
            CustomData: 'Awaiting clearfin_sentinel approval for security-sensitive deployment',
            NotificationArn: `clearfin-${env}-sentinel-notifications`,
          },
        },
      ],
    },
    {
      name: 'Deploy',
      order: 5,
      actions: [
        {
          name: 'DeployServices',
          type: 'deploy' as const,
          provider: 'ECS',
          configuration: {
            ClusterName: `clearfin-${env}-cluster`,
          },
        },
        {
          name: 'DeployLoginPage',
          type: 'deploy' as const,
          provider: 'S3',
          configuration: {
            BucketName: `clearfin-${env}-login-page`,
          },
        },
      ],
    },
  ];

  // Req 5.2: Validate artifact includes IAM, STS trust, and Secrets Manager policies
  const sentinelGate: SentinelGateStageConfig = {
    name: `clearfin-${env}-sentinel-gate`,
    artifactValidation: {
      requiredComponents: [
        'iam-policy-documents',
        'sts-trust-policies',
        'secrets-manager-resource-policies',
      ],
      hashAlgorithm: 'SHA-256' as const,
    },
    approvalConfig: {
      approverIdentity: 'clearfin_sentinel',
      timeoutMinutes: 60,
      onTimeout: 'halt' as const,
      onRejection: 'halt' as const, // Req 5.3: halt pipeline on rejection
    },
    auditLogConfig: {
      logGroupName: `/clearfin/${env}/sentinel-gate/audit`,
      retentionDays: 365,
      immutable: true,
    },
  };

  return {
    name: `clearfin-${env}-pipeline`,
    stages,
    sentinelGate,
    ecrRepositories: [
      'clearfin/auth-service',
      'clearfin/sts-broker',
      'clearfin/secrets-hierarchy-manager',
    ],
    s3DeployBucket: `clearfin-${env}-login-page`,
    tags: {
      Project: 'ClearFin',
      Environment: env,
      Component: 'cicd',
    },
  };
}
