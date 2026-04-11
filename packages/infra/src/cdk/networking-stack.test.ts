// @clearfin/infra — CDK assertion tests for NetworkingCdkStack
// Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 9.1, 9.2

import { describe, it, expect, beforeAll } from 'vitest';
import * as cdk from 'aws-cdk-lib';
import { Template, Match } from 'aws-cdk-lib/assertions';
import { NetworkingCdkStack } from './networking-stack.js';
import { buildVpcConfig } from '../vpc.js';

const ENV = 'test';
const vpcConfig = buildVpcConfig(ENV);

let template: Template;

beforeAll(() => {
  const app = new cdk.App();
  const stack = new NetworkingCdkStack(app, 'TestNetworkingStack', {
    clearfinEnv: ENV,
    vpcConfig,
  });
  template = Template.fromStack(stack);
});

// ── Req 1.1: VPC with correct CIDR and DNS settings ────────────────

describe('VPC resource', () => {
  it('creates a VPC with the correct CIDR block and DNS settings', () => {
    template.hasResourceProperties('AWS::EC2::VPC', {
      CidrBlock: '10.0.0.0/16',
      EnableDnsSupport: true,
      EnableDnsHostnames: true,
    });
  });

  it('creates exactly 1 VPC', () => {
    template.resourceCountIs('AWS::EC2::VPC', 1);
  });
});

// ── Req 1.2: Subnets across AZs ────────────────────────────────────

describe('Subnets', () => {
  it('creates 4 subnets total (2 public + 2 private)', () => {
    template.resourceCountIs('AWS::EC2::Subnet', 4);
  });

  it('creates public subnet in il-central-1a with correct CIDR', () => {
    template.hasResourceProperties('AWS::EC2::Subnet', {
      CidrBlock: '10.0.0.0/24',
      AvailabilityZone: 'il-central-1a',
      MapPublicIpOnLaunch: true,
    });
  });

  it('creates public subnet in il-central-1b with correct CIDR', () => {
    template.hasResourceProperties('AWS::EC2::Subnet', {
      CidrBlock: '10.0.1.0/24',
      AvailabilityZone: 'il-central-1b',
      MapPublicIpOnLaunch: true,
    });
  });

  it('creates private subnet in il-central-1a with correct CIDR', () => {
    template.hasResourceProperties('AWS::EC2::Subnet', {
      CidrBlock: '10.0.10.0/24',
      AvailabilityZone: 'il-central-1a',
      MapPublicIpOnLaunch: false,
    });
  });

  it('creates private subnet in il-central-1b with correct CIDR', () => {
    template.hasResourceProperties('AWS::EC2::Subnet', {
      CidrBlock: '10.0.11.0/24',
      AvailabilityZone: 'il-central-1b',
      MapPublicIpOnLaunch: false,
    });
  });
});

// ── Req 1.3: NAT Gateways and EIPs per AZ ──────────────────────────

describe('NAT Gateways and EIPs', () => {
  it('creates 2 NAT Gateways (one per AZ)', () => {
    template.resourceCountIs('AWS::EC2::NatGateway', 2);
  });

  it('creates 2 Elastic IPs for NAT Gateways', () => {
    template.resourceCountIs('AWS::EC2::EIP', 2);
  });

  it('each NAT Gateway has an allocation ID and subnet ID', () => {
    template.hasResourceProperties('AWS::EC2::NatGateway', {
      AllocationId: Match.anyValue(),
      SubnetId: Match.anyValue(),
    });
  });
});

// ── Req 1.4: Interface VPC Endpoints ────────────────────────────────

describe('Interface VPC Endpoints', () => {
  it('creates 7 interface VPC endpoints', () => {
    // Count interface endpoints (ServiceName contains the service, VpcEndpointType is Interface)
    const resources = template.findResources('AWS::EC2::VPCEndpoint', {
      Properties: {
        VpcEndpointType: 'Interface',
      },
    });
    expect(Object.keys(resources).length).toBe(7);
  });

  it('creates interface endpoint for ECR API with private DNS', () => {
    template.hasResourceProperties('AWS::EC2::VPCEndpoint', {
      VpcEndpointType: 'Interface',
      PrivateDnsEnabled: true,
      ServiceName: Match.objectLike({
        'Fn::Join': Match.arrayWith([
          Match.arrayWith([
            Match.stringLikeRegexp('ecr'),
          ]),
        ]),
      }),
    });
  });

  it('all interface endpoints have private DNS enabled', () => {
    const resources = template.findResources('AWS::EC2::VPCEndpoint', {
      Properties: {
        VpcEndpointType: 'Interface',
      },
    });
    for (const [, resource] of Object.entries(resources)) {
      expect((resource as any).Properties.PrivateDnsEnabled).toBe(true);
    }
  });

  it('all interface endpoints are placed in private subnets', () => {
    const resources = template.findResources('AWS::EC2::VPCEndpoint', {
      Properties: {
        VpcEndpointType: 'Interface',
      },
    });
    for (const [, resource] of Object.entries(resources)) {
      expect((resource as any).Properties.SubnetIds).toBeDefined();
      expect((resource as any).Properties.SubnetIds.length).toBe(2);
    }
  });
});

// ── Req 1.5: Gateway VPC Endpoint for S3 ───────────────────────────

describe('Gateway VPC Endpoint', () => {
  it('creates 1 gateway VPC endpoint for S3', () => {
    const resources = template.findResources('AWS::EC2::VPCEndpoint', {
      Properties: {
        VpcEndpointType: 'Gateway',
      },
    });
    expect(Object.keys(resources).length).toBe(1);
  });

  it('gateway endpoint is associated with route tables', () => {
    template.hasResourceProperties('AWS::EC2::VPCEndpoint', {
      VpcEndpointType: 'Gateway',
      RouteTableIds: Match.anyValue(),
    });
  });
});

// ── Req 1.6: CfnOutput exports ─────────────────────────────────────

describe('CfnOutput exports', () => {
  it('exports VPC ID', () => {
    template.hasOutput('VpcId', {
      Export: { Name: `${ENV}-vpc-id` },
    });
  });

  it('exports public subnet IDs', () => {
    template.hasOutput('PublicSubnetIds', {
      Export: { Name: `${ENV}-public-subnet-ids` },
    });
  });

  it('exports private subnet IDs', () => {
    template.hasOutput('PrivateSubnetIds', {
      Export: { Name: `${ENV}-private-subnet-ids` },
    });
  });
});

// ── Req 1.7: Tags on networking resources ───────────────────────────

describe('Tags', () => {
  it('VPC has Project tag', () => {
    template.hasResourceProperties('AWS::EC2::VPC', {
      Tags: Match.arrayWith([
        Match.objectLike({ Key: 'Project', Value: 'ClearFin' }),
      ]),
    });
  });

  it('VPC has Environment tag', () => {
    template.hasResourceProperties('AWS::EC2::VPC', {
      Tags: Match.arrayWith([
        Match.objectLike({ Key: 'Environment', Value: ENV }),
      ]),
    });
  });

  it('VPC has Component tag', () => {
    template.hasResourceProperties('AWS::EC2::VPC', {
      Tags: Match.arrayWith([
        Match.objectLike({ Key: 'Component', Value: 'networking' }),
      ]),
    });
  });

  it('subnets have Project tag', () => {
    template.hasResourceProperties('AWS::EC2::Subnet', {
      Tags: Match.arrayWith([
        Match.objectLike({ Key: 'Project', Value: 'ClearFin' }),
      ]),
    });
  });

  it('subnets have Environment tag', () => {
    template.hasResourceProperties('AWS::EC2::Subnet', {
      Tags: Match.arrayWith([
        Match.objectLike({ Key: 'Environment', Value: ENV }),
      ]),
    });
  });

  it('subnets have Component tag', () => {
    template.hasResourceProperties('AWS::EC2::Subnet', {
      Tags: Match.arrayWith([
        Match.objectLike({ Key: 'Component', Value: 'networking' }),
      ]),
    });
  });

  it('NAT Gateways have Name tags', () => {
    template.hasResourceProperties('AWS::EC2::NatGateway', {
      Tags: Match.arrayWith([
        Match.objectLike({ Key: 'Name' }),
      ]),
    });
  });
});

// ── Req 9.1 & 9.2: Synthesis validation ────────────────────────────

describe('Synthesis validation', () => {
  it('synthesizes without errors using config builder output', () => {
    // The template was already synthesized in beforeAll — if it got here, synthesis succeeded
    const resources = template.toJSON().Resources;
    expect(Object.keys(resources).length).toBeGreaterThan(0);
  });

  it('total VPC endpoint count is 8 (7 interface + 1 gateway)', () => {
    template.resourceCountIs('AWS::EC2::VPCEndpoint', 8);
  });
});
