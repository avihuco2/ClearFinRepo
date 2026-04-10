// @clearfin/infra — CDK app entry point
// Validates: Requirements 4.4, 7.5

import {
  ClearFinNetworkingStack,
  ClearFinComputeStack,
  ClearFinSecurityStack,
  ClearFinStaticHostingStack,
} from './stacks.js';
import type { CdkStackContext } from './stacks.js';

export type { CdkStackContext } from './stacks.js';

export interface ClearFinApp {
  networkingStack: ClearFinNetworkingStack;
  computeStack: ClearFinComputeStack;
  securityStack: ClearFinSecurityStack;
  staticHostingStack: ClearFinStaticHostingStack;
}

/**
 * Build the full ClearFin application stack graph.
 *
 * ComputeStack depends on NetworkingStack (VPC/subnets) and
 * SecurityStack (IAM roles), so they are instantiated first and
 * passed in. The imageTag on the context flows through to
 * ComputeStack for ECS task definition image references.
 */
export function buildClearFinApp(context: CdkStackContext): ClearFinApp {
  const networkingStack = new ClearFinNetworkingStack(context);
  const securityStack = new ClearFinSecurityStack(context);
  const computeStack = new ClearFinComputeStack(context, networkingStack, securityStack);
  const staticHostingStack = new ClearFinStaticHostingStack(context);

  return { networkingStack, computeStack, securityStack, staticHostingStack };
}

/**
 * Read CdkStackContext from environment variables.
 * Used by CI/CD pipelines that pass context via env vars
 * set from GitHub Actions environment configuration.
 */
export function buildContextFromEnv(): CdkStackContext {
  const required = (name: string): string => {
    const value = process.env[name];
    if (!value) {
      throw new Error(`Missing required environment variable: ${name}`);
    }
    return value;
  };

  return {
    environment: required('CDK_ENVIRONMENT'),
    accountId: required('CDK_ACCOUNT_ID'),
    region: required('CDK_REGION'),
    imageTag: required('CDK_IMAGE_TAG'),
    domainName: required('CDK_DOMAIN_NAME'),
    certificateArn: required('CDK_CERTIFICATE_ARN'),
  };
}

/** Default region for ClearFin deployments. */
export const DEFAULT_REGION = 'il-central-1';
