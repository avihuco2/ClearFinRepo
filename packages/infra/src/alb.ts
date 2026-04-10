// @clearfin/infra — ALB with TLS 1.2+ termination and health checks
// Validates: Requirements 6.3, 6.6

export interface HealthCheckConfig {
  path: string;
  protocol: 'HTTP' | 'HTTPS';
  port: number;
  healthyThreshold: number;
  unhealthyThreshold: number;
  intervalSeconds: number;
  timeoutSeconds: number;
}

export interface TargetGroupConfig {
  name: string;
  port: number;
  protocol: 'HTTP';
  targetType: 'ip';
  healthCheck: HealthCheckConfig;
}

export interface ListenerConfig {
  port: number;
  protocol: 'HTTPS';
  sslPolicy: string;
  certificateArn: string;
  defaultAction: 'forward';
  targetGroupName: string;
}

export interface HttpRedirectListenerConfig {
  port: 80;
  protocol: 'HTTP';
  redirectTo: 'HTTPS';
  statusCode: 301;
}

export interface AlbConfig {
  name: string;
  scheme: 'internet-facing';
  subnetType: 'public';
  securityGroupRules: {
    ingressPorts: number[];
    ingressCidr: string;
  };
  listeners: ListenerConfig[];
  httpRedirectListener: HttpRedirectListenerConfig;
  targetGroups: TargetGroupConfig[];
  tags: Record<string, string>;
}

export function buildAlbConfig(env: string, certificateArn: string): AlbConfig {
  const targetGroups: TargetGroupConfig[] = [
    {
      name: `clearfin-${env}-auth-tg`,
      port: 3000,
      protocol: 'HTTP' as const,
      targetType: 'ip' as const,
      healthCheck: {
        path: '/health', // Req 6.6: health endpoint for ALB
        protocol: 'HTTP' as const,
        port: 3000,
        healthyThreshold: 2,
        unhealthyThreshold: 3,
        intervalSeconds: 30,
        timeoutSeconds: 5,
      },
    },
    {
      name: `clearfin-${env}-sts-tg`,
      port: 3001,
      protocol: 'HTTP' as const,
      targetType: 'ip' as const,
      healthCheck: {
        path: '/health',
        protocol: 'HTTP' as const,
        port: 3001,
        healthyThreshold: 2,
        unhealthyThreshold: 3,
        intervalSeconds: 30,
        timeoutSeconds: 5,
      },
    },
    {
      name: `clearfin-${env}-secrets-tg`,
      port: 3002,
      protocol: 'HTTP' as const,
      targetType: 'ip' as const,
      healthCheck: {
        path: '/health',
        protocol: 'HTTP' as const,
        port: 3002,
        healthyThreshold: 2,
        unhealthyThreshold: 3,
        intervalSeconds: 30,
        timeoutSeconds: 5,
      },
    },
  ];

  return {
    name: `clearfin-${env}-alb`,
    scheme: 'internet-facing' as const,
    subnetType: 'public',
    securityGroupRules: {
      ingressPorts: [443, 80],
      ingressCidr: '0.0.0.0/0',
    },
    listeners: [
      {
        port: 443,
        protocol: 'HTTPS' as const,
        sslPolicy: 'ELBSecurityPolicy-TLS13-1-2-2021-06', // Req 6.3: TLS 1.2+ minimum
        certificateArn,
        defaultAction: 'forward' as const,
        targetGroupName: targetGroups[0].name,
      },
    ],
    httpRedirectListener: {
      port: 80,
      protocol: 'HTTP' as const,
      redirectTo: 'HTTPS' as const,
      statusCode: 301,
    },
    targetGroups,
    tags: {
      Project: 'ClearFin',
      Environment: env,
      Component: 'load-balancer',
    },
  };
}
