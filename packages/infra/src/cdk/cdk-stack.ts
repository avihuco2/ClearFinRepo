// @clearfin/infra — Thin CDK stack wrapper around config objects
// Each stack creates an SSM parameter as a placeholder to make cdk synth/deploy work.
// Real AWS resources will be wired in incrementally from the config builders.

import * as cdk from 'aws-cdk-lib';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import { Construct } from 'constructs';

export interface ClearFinCdkStackProps extends cdk.StackProps {
  component: 'networking' | 'security' | 'compute' | 'static-hosting';
  clearfinEnv: string;
  accountId: string;
  imageTag: string;
  domainName: string;
  certificateArn: string;
}

export class ClearFinCdkStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: ClearFinCdkStackProps) {
    super(scope, id, props);

    const { component, clearfinEnv, imageTag } = props;

    // Placeholder parameter — proves the stack synthesizes and deploys.
    // Real resources will replace this as we wire config builders to CDK constructs.
    new ssm.StringParameter(this, 'StackMetadata', {
      parameterName: `/clearfin/${clearfinEnv}/${component}/version`,
      stringValue: JSON.stringify({
        component,
        environment: clearfinEnv,
        imageTag,
        deployedAt: new Date().toISOString(),
      }),
      description: `ClearFin ${clearfinEnv} ${component} stack metadata`,
    });
  }
}
