// @clearfin/infra — VPC, subnets, NAT Gateway configuration
// Validates: Requirements 6.1, 6.2

export interface SubnetConfig {
  name: string;
  type: 'public' | 'private';
  cidrBlock: string;
  availabilityZone: string;
  mapPublicIpOnLaunch: boolean;
}

export interface NatGatewayConfig {
  name: string;
  subnetName: string;
  elasticIpAllocation: boolean;
}

export interface VpcEndpointConfig {
  name: string;
  service: string;
  type: 'Interface' | 'Gateway';
  privateDnsEnabled: boolean;
  subnetType: 'private' | 'all';
}

export interface VpcConfig {
  name: string;
  cidrBlock: string;
  enableDnsSupport: boolean;
  enableDnsHostnames: boolean;
  subnets: SubnetConfig[];
  natGateways: NatGatewayConfig[];
  vpcEndpoints: VpcEndpointConfig[];
  tags: Record<string, string>;
}

const AVAILABILITY_ZONES = ['il-central-1a', 'il-central-1b'];

export function buildVpcConfig(env: string): VpcConfig {
  const publicSubnets: SubnetConfig[] = AVAILABILITY_ZONES.map((az, i) => ({
    name: `clearfin-${env}-public-${az}`,
    type: 'public' as const,
    cidrBlock: `10.0.${i}.0/24`,
    availabilityZone: az,
    mapPublicIpOnLaunch: true,
  }));

  const privateSubnets: SubnetConfig[] = AVAILABILITY_ZONES.map((az, i) => ({
    name: `clearfin-${env}-private-${az}`,
    type: 'private' as const,
    cidrBlock: `10.0.${i + 10}.0/24`,
    availabilityZone: az,
    mapPublicIpOnLaunch: false, // Req 6.1: no public IP for Fargate tasks
  }));

  const natGateways: NatGatewayConfig[] = AVAILABILITY_ZONES.map((az, i) => ({
    name: `clearfin-${env}-nat-${az}`,
    subnetName: publicSubnets[i].name,
    elasticIpAllocation: true,
  }));

  // VPC Endpoints — all AWS service traffic stays on private network (PrivateLink)
  const vpcEndpoints: VpcEndpointConfig[] = [
    // Interface endpoints (PrivateLink)
    { name: `clearfin-${env}-vpce-ecr-api`, service: 'com.amazonaws.il-central-1.ecr.api', type: 'Interface', privateDnsEnabled: true, subnetType: 'private' },
    { name: `clearfin-${env}-vpce-ecr-dkr`, service: 'com.amazonaws.il-central-1.ecr.dkr', type: 'Interface', privateDnsEnabled: true, subnetType: 'private' },
    { name: `clearfin-${env}-vpce-sts`, service: 'com.amazonaws.il-central-1.sts', type: 'Interface', privateDnsEnabled: true, subnetType: 'private' },
    { name: `clearfin-${env}-vpce-secretsmanager`, service: 'com.amazonaws.il-central-1.secretsmanager', type: 'Interface', privateDnsEnabled: true, subnetType: 'private' },
    { name: `clearfin-${env}-vpce-kms`, service: 'com.amazonaws.il-central-1.kms', type: 'Interface', privateDnsEnabled: true, subnetType: 'private' },
    { name: `clearfin-${env}-vpce-logs`, service: 'com.amazonaws.il-central-1.logs', type: 'Interface', privateDnsEnabled: true, subnetType: 'private' },
    { name: `clearfin-${env}-vpce-monitoring`, service: 'com.amazonaws.il-central-1.monitoring', type: 'Interface', privateDnsEnabled: true, subnetType: 'private' },
    // Gateway endpoints (no cost, route-table based)
    { name: `clearfin-${env}-vpce-s3`, service: 'com.amazonaws.il-central-1.s3', type: 'Gateway', privateDnsEnabled: false, subnetType: 'all' },
  ];

  return {
    name: `clearfin-${env}-vpc`,
    cidrBlock: '10.0.0.0/16',
    enableDnsSupport: true,
    enableDnsHostnames: true,
    subnets: [...publicSubnets, ...privateSubnets],
    natGateways, // Req 6.2: NAT Gateway for outbound to Google OAuth
    vpcEndpoints, // PrivateLink: all AWS service traffic stays on private network
    tags: {
      Project: 'ClearFin',
      Environment: env,
      Component: 'networking',
    },
  };
}
