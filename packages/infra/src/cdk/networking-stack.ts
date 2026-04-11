// @clearfin/infra — NetworkingCdkStack: VPC, subnets, NAT Gateways, VPC endpoints
// Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7

import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import { Construct } from 'constructs';
import type { VpcConfig } from '../vpc.js';

export interface NetworkingCdkStackProps extends cdk.StackProps {
  clearfinEnv: string;
  vpcConfig: VpcConfig;
}

export class NetworkingCdkStack extends cdk.Stack {
  public readonly vpc: ec2.Vpc;
  public readonly publicSubnets: ec2.PublicSubnet[];
  public readonly privateSubnets: ec2.PrivateSubnet[];

  constructor(scope: Construct, id: string, props: NetworkingCdkStackProps) {
    super(scope, id, props);

    const { vpcConfig, clearfinEnv } = props;

    // Req 1.7: Apply tags from VpcConfig to all resources in this stack
    for (const [key, value] of Object.entries(vpcConfig.tags)) {
      cdk.Tags.of(this).add(key, value);
    }

    // Req 1.1: Create VPC with CIDR, DNS support, DNS hostnames
    this.vpc = new ec2.Vpc(this, 'Vpc', {
      vpcName: vpcConfig.name,
      ipAddresses: ec2.IpAddresses.cidr(vpcConfig.cidrBlock),
      enableDnsSupport: vpcConfig.enableDnsSupport,
      enableDnsHostnames: vpcConfig.enableDnsHostnames,
      maxAzs: 0,
      subnetConfiguration: [],
      natGateways: 0,
    });

    // Req 1.2: Create public and private subnets across il-central-1a and il-central-1b
    const publicSubnetConfigs = vpcConfig.subnets.filter((s) => s.type === 'public');
    const privateSubnetConfigs = vpcConfig.subnets.filter((s) => s.type === 'private');

    this.publicSubnets = publicSubnetConfigs.map(
      (subnetCfg, i) =>
        new ec2.PublicSubnet(this, `PublicSubnet${i}`, {
          vpcId: this.vpc.vpcId,
          cidrBlock: subnetCfg.cidrBlock,
          availabilityZone: subnetCfg.availabilityZone,
          mapPublicIpOnLaunch: subnetCfg.mapPublicIpOnLaunch,
        }),
    );

    this.privateSubnets = privateSubnetConfigs.map(
      (subnetCfg, i) =>
        new ec2.PrivateSubnet(this, `PrivateSubnet${i}`, {
          vpcId: this.vpc.vpcId,
          cidrBlock: subnetCfg.cidrBlock,
          availabilityZone: subnetCfg.availabilityZone,
          mapPublicIpOnLaunch: subnetCfg.mapPublicIpOnLaunch,
        }),
    );

    // Req 1.3: Create one NAT Gateway per AZ in public subnets with Elastic IP
    // Build a lookup from subnet name to public subnet for NAT gateway placement
    const publicSubnetByName = new Map<string, ec2.PublicSubnet>();
    publicSubnetConfigs.forEach((cfg, i) => {
      publicSubnetByName.set(cfg.name, this.publicSubnets[i]);
    });

    vpcConfig.natGateways.forEach((natCfg, i) => {
      const publicSubnet = publicSubnetByName.get(natCfg.subnetName);
      if (!publicSubnet) {
        throw new Error(`NAT Gateway ${natCfg.name} references unknown subnet ${natCfg.subnetName}`);
      }

      // Create Elastic IP for the NAT Gateway
      const eip = new ec2.CfnEIP(this, `NatEip${i}`, {
        domain: 'vpc',
      });

      // Create NAT Gateway in the public subnet
      const natGw = new ec2.CfnNatGateway(this, `NatGateway${i}`, {
        subnetId: publicSubnet.subnetId,
        allocationId: eip.attrAllocationId,
        tags: [{ key: 'Name', value: natCfg.name }],
      });

      // Add default route in the corresponding private subnet to this NAT Gateway
      if (i < this.privateSubnets.length) {
        this.privateSubnets[i].addRoute('DefaultNatRoute', {
          routerId: natGw.ref,
          routerType: ec2.RouterType.NAT_GATEWAY,
          destinationCidrBlock: '0.0.0.0/0',
        });
      }
    });

    // Create Internet Gateway explicitly since VPC was created with no subnets
    const igw = new ec2.CfnInternetGateway(this, 'InternetGateway', {
      tags: [{ key: 'Name', value: `${vpcConfig.name}-igw` }],
    });

    new ec2.CfnVPCGatewayAttachment(this, 'VpcIgwAttachment', {
      vpcId: this.vpc.vpcId,
      internetGatewayId: igw.ref,
    });

    // Add internet gateway routes for public subnets
    for (const pubSubnet of this.publicSubnets) {
      pubSubnet.addRoute('DefaultIgwRoute', {
        routerId: igw.ref,
        routerType: ec2.RouterType.GATEWAY,
        destinationCidrBlock: '0.0.0.0/0',
      });
    }

    // Req 1.4 & 1.5: Create VPC endpoints
    // Map service name suffixes to CDK InterfaceVpcEndpointAwsService
    const interfaceServiceMap: Record<string, ec2.InterfaceVpcEndpointAwsService> = {
      'ecr.api': ec2.InterfaceVpcEndpointAwsService.ECR,
      'ecr.dkr': ec2.InterfaceVpcEndpointAwsService.ECR_DOCKER,
      'sts': ec2.InterfaceVpcEndpointAwsService.STS,
      'secretsmanager': ec2.InterfaceVpcEndpointAwsService.SECRETS_MANAGER,
      'kms': ec2.InterfaceVpcEndpointAwsService.KMS,
      'logs': ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_LOGS,
      'monitoring': ec2.InterfaceVpcEndpointAwsService.CLOUDWATCH_MONITORING,
    };

    for (const epCfg of vpcConfig.vpcEndpoints) {
      // Extract the service suffix from the full service name (e.g., 'com.amazonaws.il-central-1.ecr.api' → 'ecr.api')
      const parts = epCfg.service.split('.');
      // Service suffix is everything after the region part (index 3+)
      const serviceSuffix = parts.slice(3).join('.');

      if (epCfg.type === 'Interface') {
        const awsService = interfaceServiceMap[serviceSuffix];
        if (!awsService) {
          throw new Error(`Unknown interface VPC endpoint service: ${epCfg.service}`);
        }

        new ec2.InterfaceVpcEndpoint(this, `VpcEndpoint-${serviceSuffix.replace(/\./g, '-')}`, {
          vpc: this.vpc,
          service: awsService,
          subnets: { subnets: this.privateSubnets },
          privateDnsEnabled: epCfg.privateDnsEnabled,
        });
      } else if (epCfg.type === 'Gateway') {
        // Req 1.5: Gateway endpoint for S3 associated with all route tables
        const allSubnets = [...this.publicSubnets, ...this.privateSubnets];
        new ec2.GatewayVpcEndpoint(this, `VpcEndpoint-${serviceSuffix}`, {
          vpc: this.vpc,
          service: ec2.GatewayVpcEndpointAwsService.S3,
          subnets: [{ subnets: allSubnets }],
        });
      }
    }

    // Req 1.6: Export VPC ID, public subnet IDs, private subnet IDs as CfnOutputs
    new cdk.CfnOutput(this, 'VpcId', {
      value: this.vpc.vpcId,
      exportName: `${clearfinEnv}-vpc-id`,
    });

    new cdk.CfnOutput(this, 'PublicSubnetIds', {
      value: this.publicSubnets.map((s) => s.subnetId).join(','),
      exportName: `${clearfinEnv}-public-subnet-ids`,
    });

    new cdk.CfnOutput(this, 'PrivateSubnetIds', {
      value: this.privateSubnets.map((s) => s.subnetId).join(','),
      exportName: `${clearfinEnv}-private-subnet-ids`,
    });
  }
}
