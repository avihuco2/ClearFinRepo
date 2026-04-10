// @clearfin/infra — ECS Fargate cluster and service definitions
// Validates: Requirements 6.1

export interface TaskDefinitionConfig {
  family: string;
  cpu: number;
  memory: number;
  ecrRepository: string;
  containerPort: number;
  user: string;
  environment: Record<string, string>;
  healthCheckPath: string;
  executionRoleName: string;
  taskRoleName: string;
}

export interface FargateServiceConfig {
  name: string;
  desiredCount: number;
  assignPublicIp: boolean;
  subnetType: 'private';
  taskDefinition: TaskDefinitionConfig;
}

export interface EcsClusterConfig {
  name: string;
  containerInsights: boolean;
  services: FargateServiceConfig[];
  tags: Record<string, string>;
}

const SERVICE_DEFINITIONS: Array<{
  serviceName: string;
  ecrRepo: string;
  port: number;
  healthCheck: string;
}> = [
  { serviceName: 'auth-service', ecrRepo: 'clearfin/auth-service', port: 3000, healthCheck: '/health' },
  { serviceName: 'sts-broker', ecrRepo: 'clearfin/sts-broker', port: 3001, healthCheck: '/health' },
  { serviceName: 'secrets-hierarchy-manager', ecrRepo: 'clearfin/secrets-hierarchy-manager', port: 3002, healthCheck: '/health' },
];

export function buildEcsClusterConfig(env: string): EcsClusterConfig {
  const services: FargateServiceConfig[] = SERVICE_DEFINITIONS.map((svc) => ({
    name: `clearfin-${svc.serviceName}`,
    desiredCount: env === 'prod' ? 2 : 1,
    assignPublicIp: false, // Req 6.1: private subnets only
    subnetType: 'private' as const,
    taskDefinition: {
      family: `clearfin-${env}-${svc.serviceName}`,
      cpu: 256,
      memory: 512,
      ecrRepository: svc.ecrRepo,
      containerPort: svc.port,
      user: '1000:1000', // Non-root user execution
      environment: {
        NODE_ENV: env,
        SERVICE_NAME: svc.serviceName,
      },
      healthCheckPath: svc.healthCheck,
      executionRoleName: `clearfin-${env}-${svc.serviceName}-execution`,
      taskRoleName: `clearfin-${env}-${svc.serviceName}-task`,
    },
  }));

  return {
    name: `clearfin-${env}-cluster`,
    containerInsights: true,
    services,
    tags: {
      Project: 'ClearFin',
      Environment: env,
      Component: 'compute',
    },
  };
}
