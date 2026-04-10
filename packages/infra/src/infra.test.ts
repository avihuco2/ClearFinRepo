import { describe, it, expect } from 'vitest';
import { buildVpcConfig } from './vpc.js';
import { buildEcsClusterConfig } from './ecs.js';
import { buildEcrRepositoryConfigs } from './ecr.js';
import { buildAlbConfig } from './alb.js';
import { buildCloudFrontConfig } from './cloudfront.js';
import { buildIamConfig } from './iam.js';
import { buildCloudTrailConfig } from './cloudtrail.js';
import { buildPipelineConfig } from './pipeline.js';

// ── Task 12.1: VPC ──────────────────────────────────────────────────

describe('VPC configuration', () => {
  const vpc = buildVpcConfig('prod');

  it('creates VPC with correct naming', () => {
    expect(vpc.name).toBe('clearfin-prod-vpc');
    expect(vpc.cidrBlock).toBe('10.0.0.0/16');
  });

  it('enables DNS support and hostnames', () => {
    expect(vpc.enableDnsSupport).toBe(true);
    expect(vpc.enableDnsHostnames).toBe(true);
  });

  it('creates both public and private subnets', () => {
    const publicSubnets = vpc.subnets.filter((s) => s.type === 'public');
    const privateSubnets = vpc.subnets.filter((s) => s.type === 'private');
    expect(publicSubnets.length).toBeGreaterThanOrEqual(2);
    expect(privateSubnets.length).toBeGreaterThanOrEqual(2);
  });

  it('private subnets do not assign public IPs (Req 6.1)', () => {
    const privateSubnets = vpc.subnets.filter((s) => s.type === 'private');
    for (const subnet of privateSubnets) {
      expect(subnet.mapPublicIpOnLaunch).toBe(false);
    }
  });

  it('creates NAT gateways in public subnets (Req 6.2)', () => {
    expect(vpc.natGateways.length).toBeGreaterThanOrEqual(1);
    const publicSubnetNames = vpc.subnets
      .filter((s) => s.type === 'public')
      .map((s) => s.name);
    for (const nat of vpc.natGateways) {
      expect(publicSubnetNames).toContain(nat.subnetName);
    }
  });

  it('includes environment tag', () => {
    expect(vpc.tags.Environment).toBe('prod');
  });

  it('creates VPC endpoints for all required AWS services (PrivateLink)', () => {
    expect(vpc.vpcEndpoints.length).toBeGreaterThanOrEqual(8);
    const services = vpc.vpcEndpoints.map((e) => e.service);
    expect(services).toContain('com.amazonaws.il-central-1.ecr.api');
    expect(services).toContain('com.amazonaws.il-central-1.ecr.dkr');
    expect(services).toContain('com.amazonaws.il-central-1.sts');
    expect(services).toContain('com.amazonaws.il-central-1.secretsmanager');
    expect(services).toContain('com.amazonaws.il-central-1.kms');
    expect(services).toContain('com.amazonaws.il-central-1.logs');
    expect(services).toContain('com.amazonaws.il-central-1.s3');
  });

  it('interface endpoints have private DNS enabled and target private subnets', () => {
    const interfaceEndpoints = vpc.vpcEndpoints.filter((e) => e.type === 'Interface');
    expect(interfaceEndpoints.length).toBeGreaterThanOrEqual(6);
    for (const ep of interfaceEndpoints) {
      expect(ep.privateDnsEnabled).toBe(true);
      expect(ep.subnetType).toBe('private');
    }
  });

  it('S3 endpoint is a Gateway type', () => {
    const s3Endpoint = vpc.vpcEndpoints.find((e) => e.service.includes('.s3'));
    expect(s3Endpoint).toBeDefined();
    expect(s3Endpoint!.type).toBe('Gateway');
  });
});

// ── Task 12.2: ECS Fargate ──────────────────────────────────────────

describe('ECS Fargate configuration', () => {
  const cluster = buildEcsClusterConfig('prod');

  it('creates cluster with correct naming', () => {
    expect(cluster.name).toBe('clearfin-prod-cluster');
  });

  it('enables container insights', () => {
    expect(cluster.containerInsights).toBe(true);
  });

  it('defines three Fargate services', () => {
    expect(cluster.services).toHaveLength(3);
    const names = cluster.services.map((s) => s.name);
    expect(names).toContain('clearfin-auth-service');
    expect(names).toContain('clearfin-sts-broker');
    expect(names).toContain('clearfin-secrets-hierarchy-manager');
  });

  it('all services use private subnets with no public IP (Req 6.1)', () => {
    for (const svc of cluster.services) {
      expect(svc.assignPublicIp).toBe(false);
      expect(svc.subnetType).toBe('private');
    }
  });

  it('task definitions use non-root user', () => {
    for (const svc of cluster.services) {
      expect(svc.taskDefinition.user).toBe('1000:1000');
    }
  });

  it('prod environment has desiredCount of 2', () => {
    for (const svc of cluster.services) {
      expect(svc.taskDefinition.family).toContain('prod');
      expect(svc.desiredCount).toBe(2);
    }
  });

  it('dev environment has desiredCount of 1', () => {
    const devCluster = buildEcsClusterConfig('dev');
    for (const svc of devCluster.services) {
      expect(svc.desiredCount).toBe(1);
    }
  });
});

// ── Task 12.3: ECR ──────────────────────────────────────────────────

describe('ECR repository configuration', () => {
  const repos = buildEcrRepositoryConfigs('prod');

  it('creates three repositories', () => {
    expect(repos).toHaveLength(3);
    const names = repos.map((r) => r.name);
    expect(names).toContain('clearfin/auth-service');
    expect(names).toContain('clearfin/sts-broker');
    expect(names).toContain('clearfin/secrets-hierarchy-manager');
  });

  it('enforces image tag immutability', () => {
    for (const repo of repos) {
      expect(repo.imageTagMutability).toBe('IMMUTABLE');
    }
  });

  it('enables scan on push', () => {
    for (const repo of repos) {
      expect(repo.scanOnPush).toBe(true);
    }
  });

  it('uses KMS encryption', () => {
    for (const repo of repos) {
      expect(repo.encryptionType).toBe('KMS');
    }
  });

  it('has lifecycle rules for tagged and untagged images', () => {
    for (const repo of repos) {
      expect(repo.lifecycleRules).toHaveLength(2);
      const tagged = repo.lifecycleRules.find((r) => r.tagStatus === 'tagged');
      const untagged = repo.lifecycleRules.find((r) => r.tagStatus === 'untagged');
      expect(tagged?.countNumber).toBe(10);
      expect(untagged?.countNumber).toBe(7);
    }
  });

  it('restricts push to CI/CD pipeline role and pull to execution roles', () => {
    for (const repo of repos) {
      expect(repo.repositoryPolicy.allowPushRoles[0]).toContain('cicd-pipeline');
      expect(repo.repositoryPolicy.allowPullRoles[0]).toContain('execution');
    }
  });
});

// ── Task 12.4: ALB ──────────────────────────────────────────────────

describe('ALB configuration', () => {
  const certArn = 'arn:aws:acm:il-central-1:123456789012:certificate/test-cert';
  const alb = buildAlbConfig('prod', certArn);

  it('creates ALB with correct naming', () => {
    expect(alb.name).toBe('clearfin-prod-alb');
  });

  it('is internet-facing in public subnets', () => {
    expect(alb.scheme).toBe('internet-facing');
    expect(alb.subnetType).toBe('public');
  });

  it('enforces TLS 1.2+ on HTTPS listener (Req 6.3)', () => {
    const httpsListener = alb.listeners.find((l) => l.port === 443);
    expect(httpsListener).toBeDefined();
    expect(httpsListener!.protocol).toBe('HTTPS');
    expect(httpsListener!.sslPolicy).toContain('TLS');
  });

  it('redirects HTTP to HTTPS', () => {
    expect(alb.httpRedirectListener.port).toBe(80);
    expect(alb.httpRedirectListener.redirectTo).toBe('HTTPS');
    expect(alb.httpRedirectListener.statusCode).toBe(301);
  });

  it('configures health checks targeting /health (Req 6.6)', () => {
    for (const tg of alb.targetGroups) {
      expect(tg.healthCheck.path).toBe('/health');
    }
  });

  it('defines target groups for all three services', () => {
    expect(alb.targetGroups).toHaveLength(3);
  });
});

// ── Task 12.5: CloudFront + S3 ──────────────────────────────────────

describe('CloudFront and S3 configuration', () => {
  const cf = buildCloudFrontConfig('prod', 'https://app.clearfin.com');

  it('creates S3 bucket with public access fully blocked', () => {
    const block = cf.s3Bucket.blockPublicAccess;
    expect(block.blockPublicAcls).toBe(true);
    expect(block.blockPublicPolicy).toBe(true);
    expect(block.ignorePublicAcls).toBe(true);
    expect(block.restrictPublicBuckets).toBe(true);
  });

  it('uses HTTPS-only viewer protocol (Req 8.6)', () => {
    expect(cf.distribution.viewerProtocolPolicy).toBe('redirect-to-https');
  });

  it('configures Origin Access Control for S3', () => {
    expect(cf.distribution.originAccessControl.signingProtocol).toBe('sigv4');
    expect(cf.distribution.originAccessControl.originType).toBe('s3');
  });

  it('sets Content-Security-Policy header (Req 8.6)', () => {
    const csp = cf.distribution.responseHeadersPolicy.securityHeaders.contentSecurityPolicy;
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain('script-src');
  });

  it('sets security headers including HSTS and X-Frame-Options', () => {
    const headers = cf.distribution.responseHeadersPolicy.securityHeaders;
    expect(headers.strictTransportSecurity).toContain('max-age=31536000');
    expect(headers.frameOptions).toBe('DENY');
    expect(headers.contentTypeOptions).toBe(true);
  });

  it('configures SPA error responses for 403/404', () => {
    expect(cf.distribution.errorResponses).toHaveLength(2);
    const codes = cf.distribution.errorResponses.map((e) => e.httpStatus);
    expect(codes).toContain(403);
    expect(codes).toContain(404);
  });
});

// ── Task 12.6: IAM + KMS ────────────────────────────────────────────

describe('IAM and KMS configuration', () => {
  const iam = buildIamConfig('prod', '123456789012', 'il-central-1');

  it('creates a per-environment KMS key (Req 2.2, 4.3)', () => {
    expect(iam.kmsKeys).toHaveLength(1);
    expect(iam.kmsKeys[0].alias).toBe('clearfin-prod-secrets-key');
    expect(iam.kmsKeys[0].enableKeyRotation).toBe(true);
    expect(iam.kmsKeys[0].keySpec).toBe('SYMMETRIC_DEFAULT');
  });

  it('creates execution roles, task roles, and STS base role', () => {
    // 3 execution + 3 task + 1 STS base = 7
    expect(iam.roles).toHaveLength(7);
  });

  it('execution roles trust ecs-tasks.amazonaws.com', () => {
    const execRoles = iam.roles.filter((r) => r.name.includes('execution'));
    expect(execRoles).toHaveLength(3);
    for (const role of execRoles) {
      const principal = role.trustPolicy.Statement[0].Principal;
      expect('Service' in principal && principal.Service).toBe('ecs-tasks.amazonaws.com');
    }
  });

  it('STS base role trusts the STS broker task role (Req 4.8)', () => {
    const stsBase = iam.roles.find((r) => r.name.includes('sts-base-role'));
    expect(stsBase).toBeDefined();
    const principal = stsBase!.trustPolicy.Statement[0].Principal;
    expect('AWS' in principal && principal.AWS).toContain('sts-broker-task');
  });

  it('task roles have KMS decrypt permissions', () => {
    const taskRoles = iam.roles.filter(
      (r) => r.name.includes('-task') && !r.name.includes('execution') && !r.name.includes('base')
    );
    expect(taskRoles).toHaveLength(3);
    for (const role of taskRoles) {
      const kmsPolicy = role.inlinePolicies.find((p) => p.name === 'kms-decrypt');
      expect(kmsPolicy).toBeDefined();
      expect(kmsPolicy!.statements[0].Action).toContain('kms:Decrypt');
    }
  });
});

// ── Task 12.7: CloudTrail ───────────────────────────────────────────

describe('CloudTrail configuration', () => {
  const trail = buildCloudTrailConfig('prod', '123456789012', 'il-central-1');

  it('creates trail with correct naming', () => {
    expect(trail.name).toBe('clearfin-prod-audit-trail');
  });

  it('enables log file validation', () => {
    expect(trail.enableLogFileValidation).toBe(true);
  });

  it('monitors Secrets Manager data events (Req 6.5)', () => {
    const smSelector = trail.eventSelectors[0].dataResources.find(
      (r) => r.type === 'AWS::SecretsManager::Secret'
    );
    expect(smSelector).toBeDefined();
    expect(smSelector!.values[0]).toContain('/clearfin/prod/');
  });

  it('monitors IAM, STS, and Secrets Manager API calls (Req 6.4)', () => {
    expect(trail.monitoredApiCalls).toContain('iam:PutRolePolicy');
    expect(trail.monitoredApiCalls).toContain('iam:UpdateAssumeRolePolicy');
    expect(trail.monitoredApiCalls).toContain('secretsmanager:PutResourcePolicy');
  });

  it('defines alert rules for policy modifications (Req 6.4)', () => {
    expect(trail.alertRules.length).toBeGreaterThanOrEqual(3);
    const iamAlert = trail.alertRules.find((r) => r.name.includes('iam-policy'));
    expect(iamAlert).toBeDefined();
    expect(iamAlert!.targetSnsTopicName).toContain('security-alerts');
  });

  it('uses KMS encryption for trail logs', () => {
    expect(trail.kmsKeyAlias).toBe('clearfin-prod-secrets-key');
  });
});

// ── Task 12.8: Pipeline ─────────────────────────────────────────────

describe('Pipeline configuration', () => {
  const pipeline = buildPipelineConfig('prod');

  it('creates pipeline with correct naming', () => {
    expect(pipeline.name).toBe('clearfin-prod-pipeline');
  });

  it('has 5 stages in correct order', () => {
    expect(pipeline.stages).toHaveLength(5);
    expect(pipeline.stages[0].name).toBe('Source');
    expect(pipeline.stages[1].name).toBe('Build');
    expect(pipeline.stages[2].name).toBe('ArtifactValidation');
    expect(pipeline.stages[3].name).toBe('SentinelApproval');
    expect(pipeline.stages[4].name).toBe('Deploy');
  });

  it('includes sentinel approval stage that blocks promotion (Req 5.1)', () => {
    const approvalStage = pipeline.stages.find((s) => s.name === 'SentinelApproval');
    expect(approvalStage).toBeDefined();
    const approvalAction = approvalStage!.actions.find((a) => a.type === 'approval');
    expect(approvalAction).toBeDefined();
  });

  it('validates artifact includes required security components (Req 5.2)', () => {
    const required = pipeline.sentinelGate.artifactValidation.requiredComponents;
    expect(required).toContain('iam-policy-documents');
    expect(required).toContain('sts-trust-policies');
    expect(required).toContain('secrets-manager-resource-policies');
  });

  it('halts pipeline on rejection (Req 5.3)', () => {
    expect(pipeline.sentinelGate.approvalConfig.onRejection).toBe('halt');
    expect(pipeline.sentinelGate.approvalConfig.onTimeout).toBe('halt');
  });

  it('uses clearfin_sentinel as approver identity', () => {
    expect(pipeline.sentinelGate.approvalConfig.approverIdentity).toBe('clearfin_sentinel');
  });

  it('configures immutable audit log', () => {
    expect(pipeline.sentinelGate.auditLogConfig.immutable).toBe(true);
    expect(pipeline.sentinelGate.auditLogConfig.retentionDays).toBe(365);
  });

  it('includes artifact validation stage before approval', () => {
    const validationStage = pipeline.stages.find((s) => s.name === 'ArtifactValidation');
    const approvalStage = pipeline.stages.find((s) => s.name === 'SentinelApproval');
    expect(validationStage!.order).toBeLessThan(approvalStage!.order);
  });
});
