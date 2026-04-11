// @clearfin/infra — CDK assertion tests for StaticHostingCdkStack
// Validates: Requirements 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 9.1

import { describe, it, expect, beforeAll } from 'vitest';
import * as cdk from 'aws-cdk-lib';
import { Template, Match } from 'aws-cdk-lib/assertions';
import { StaticHostingCdkStack } from './static-hosting-stack.js';
import { buildCloudFrontConfig } from '../cloudfront.js';

const ENV = 'test';
const APP_ORIGIN = 'https://test.clearfin.example.com';
const cloudFrontConfig = buildCloudFrontConfig(ENV, APP_ORIGIN);

let template: Template;

beforeAll(() => {
  const app = new cdk.App();
  const stack = new StaticHostingCdkStack(app, 'TestStaticHostingStack', {
    clearfinEnv: ENV,
    cloudFrontConfig,
  });
  template = Template.fromStack(stack);
});

// ── Req 7.1: S3 bucket with public access blocked, encryption, versioning ──

describe('S3 Bucket', () => {
  it('creates exactly 1 S3 bucket', () => {
    template.resourceCountIs('AWS::S3::Bucket', 1);
  });

  it('creates S3 bucket with the correct name', () => {
    template.hasResourceProperties('AWS::S3::Bucket', {
      BucketName: `clearfin-${ENV}-login-page`,
    });
  });

  it('creates S3 bucket with all public access blocked', () => {
    template.hasResourceProperties('AWS::S3::Bucket', {
      PublicAccessBlockConfiguration: {
        BlockPublicAcls: true,
        BlockPublicPolicy: true,
        IgnorePublicAcls: true,
        RestrictPublicBuckets: true,
      },
    });
  });

  it('creates S3 bucket with AES-256 encryption', () => {
    template.hasResourceProperties('AWS::S3::Bucket', {
      BucketEncryption: Match.objectLike({
        ServerSideEncryptionConfiguration: Match.arrayWith([
          Match.objectLike({
            ServerSideEncryptionByDefault: {
              SSEAlgorithm: 'AES256',
            },
          }),
        ]),
      }),
    });
  });

  it('creates S3 bucket with versioning enabled', () => {
    template.hasResourceProperties('AWS::S3::Bucket', {
      VersioningConfiguration: { Status: 'Enabled' },
    });
  });
});

// ── Req 7.2: CloudFront distribution with OAC ──────────────────────

describe('CloudFront Distribution', () => {
  it('creates exactly 1 CloudFront distribution', () => {
    template.resourceCountIs('AWS::CloudFront::Distribution', 1);
  });

  it('creates an Origin Access Control resource', () => {
    template.resourceCountIs('AWS::CloudFront::OriginAccessControl', 1);
  });

  it('OAC uses SigV4 signing for S3', () => {
    template.hasResourceProperties('AWS::CloudFront::OriginAccessControl', {
      OriginAccessControlConfig: Match.objectLike({
        SigningProtocol: 'sigv4',
        SigningBehavior: 'always',
        OriginAccessControlOriginType: 's3',
      }),
    });
  });

  // ── Req 7.3: redirect-to-https, HTTP/2+3, default root object ────

  it('configures redirect-to-https viewer protocol policy', () => {
    template.hasResourceProperties('AWS::CloudFront::Distribution', {
      DistributionConfig: Match.objectLike({
        DefaultCacheBehavior: Match.objectLike({
          ViewerProtocolPolicy: 'redirect-to-https',
        }),
      }),
    });
  });

  it('configures HTTP/2 and HTTP/3', () => {
    template.hasResourceProperties('AWS::CloudFront::Distribution', {
      DistributionConfig: Match.objectLike({
        HttpVersion: 'http2and3',
      }),
    });
  });

  it('configures index.html as default root object', () => {
    template.hasResourceProperties('AWS::CloudFront::Distribution', {
      DistributionConfig: Match.objectLike({
        DefaultRootObject: 'index.html',
      }),
    });
  });

  it('distribution is enabled', () => {
    template.hasResourceProperties('AWS::CloudFront::Distribution', {
      DistributionConfig: Match.objectLike({
        Enabled: true,
      }),
    });
  });

  // ── Req 7.5: Custom error responses for 403 and 404 ──────────────

  it('configures custom error response for 403', () => {
    template.hasResourceProperties('AWS::CloudFront::Distribution', {
      DistributionConfig: Match.objectLike({
        CustomErrorResponses: Match.arrayWith([
          Match.objectLike({
            ErrorCode: 403,
            ResponsePagePath: '/index.html',
            ResponseCode: 200,
          }),
        ]),
      }),
    });
  });

  it('configures custom error response for 404', () => {
    template.hasResourceProperties('AWS::CloudFront::Distribution', {
      DistributionConfig: Match.objectLike({
        CustomErrorResponses: Match.arrayWith([
          Match.objectLike({
            ErrorCode: 404,
            ResponsePagePath: '/index.html',
            ResponseCode: 200,
          }),
        ]),
      }),
    });
  });
});

// ── Req 7.4: Response headers policy with security headers ─────────

describe('Response Headers Policy', () => {
  it('creates exactly 1 response headers policy', () => {
    template.resourceCountIs('AWS::CloudFront::ResponseHeadersPolicy', 1);
  });

  it('creates response headers policy with the correct name', () => {
    template.hasResourceProperties('AWS::CloudFront::ResponseHeadersPolicy', {
      ResponseHeadersPolicyConfig: Match.objectLike({
        Name: `clearfin-${ENV}-login-headers`,
      }),
    });
  });

  it('configures Content-Security-Policy header', () => {
    template.hasResourceProperties('AWS::CloudFront::ResponseHeadersPolicy', {
      ResponseHeadersPolicyConfig: Match.objectLike({
        SecurityHeadersConfig: Match.objectLike({
          ContentSecurityPolicy: Match.objectLike({
            ContentSecurityPolicy: Match.stringLikeRegexp("default-src 'self'"),
            Override: true,
          }),
        }),
      }),
    });
  });

  it('configures Strict-Transport-Security header', () => {
    template.hasResourceProperties('AWS::CloudFront::ResponseHeadersPolicy', {
      ResponseHeadersPolicyConfig: Match.objectLike({
        SecurityHeadersConfig: Match.objectLike({
          StrictTransportSecurity: Match.objectLike({
            AccessControlMaxAgeSec: 31536000,
            IncludeSubdomains: true,
            Override: true,
          }),
        }),
      }),
    });
  });

  it('configures X-Content-Type-Options header', () => {
    template.hasResourceProperties('AWS::CloudFront::ResponseHeadersPolicy', {
      ResponseHeadersPolicyConfig: Match.objectLike({
        SecurityHeadersConfig: Match.objectLike({
          ContentTypeOptions: Match.objectLike({
            Override: true,
          }),
        }),
      }),
    });
  });

  it('configures X-Frame-Options to DENY', () => {
    template.hasResourceProperties('AWS::CloudFront::ResponseHeadersPolicy', {
      ResponseHeadersPolicyConfig: Match.objectLike({
        SecurityHeadersConfig: Match.objectLike({
          FrameOptions: Match.objectLike({
            FrameOption: 'DENY',
            Override: true,
          }),
        }),
      }),
    });
  });

  it('configures X-XSS-Protection header', () => {
    template.hasResourceProperties('AWS::CloudFront::ResponseHeadersPolicy', {
      ResponseHeadersPolicyConfig: Match.objectLike({
        SecurityHeadersConfig: Match.objectLike({
          XSSProtection: Match.objectLike({
            Protection: true,
            ModeBlock: true,
            Override: true,
          }),
        }),
      }),
    });
  });

  it('configures Referrer-Policy header', () => {
    template.hasResourceProperties('AWS::CloudFront::ResponseHeadersPolicy', {
      ResponseHeadersPolicyConfig: Match.objectLike({
        SecurityHeadersConfig: Match.objectLike({
          ReferrerPolicy: Match.objectLike({
            ReferrerPolicy: 'strict-origin-when-cross-origin',
            Override: true,
          }),
        }),
      }),
    });
  });
});


// ── Req 7.6: Tags on S3 bucket and CloudFront distribution ─────────

describe('Tags', () => {
  it('S3 bucket has Project tag', () => {
    template.hasResourceProperties('AWS::S3::Bucket', {
      Tags: Match.arrayWith([
        Match.objectLike({ Key: 'Project', Value: 'ClearFin' }),
      ]),
    });
  });

  it('S3 bucket has Environment tag', () => {
    template.hasResourceProperties('AWS::S3::Bucket', {
      Tags: Match.arrayWith([
        Match.objectLike({ Key: 'Environment', Value: ENV }),
      ]),
    });
  });

  it('S3 bucket has Component tag', () => {
    template.hasResourceProperties('AWS::S3::Bucket', {
      Tags: Match.arrayWith([
        Match.objectLike({ Key: 'Component', Value: 'login-page' }),
      ]),
    });
  });

  it('CloudFront distribution has Project tag', () => {
    template.hasResourceProperties('AWS::CloudFront::Distribution', {
      Tags: Match.arrayWith([
        Match.objectLike({ Key: 'Project', Value: 'ClearFin' }),
      ]),
    });
  });

  it('CloudFront distribution has Environment tag', () => {
    template.hasResourceProperties('AWS::CloudFront::Distribution', {
      Tags: Match.arrayWith([
        Match.objectLike({ Key: 'Environment', Value: ENV }),
      ]),
    });
  });

  it('CloudFront distribution has Component tag', () => {
    template.hasResourceProperties('AWS::CloudFront::Distribution', {
      Tags: Match.arrayWith([
        Match.objectLike({ Key: 'Component', Value: 'cdn' }),
      ]),
    });
  });
});

// ── Req 9.1: Synthesis validation ──────────────────────────────────

describe('Synthesis validation', () => {
  it('synthesizes without errors using config builder output', () => {
    const resources = template.toJSON().Resources;
    expect(Object.keys(resources).length).toBeGreaterThan(0);
  });

  it('produces expected resource types', () => {
    template.resourceCountIs('AWS::S3::Bucket', 1);
    template.resourceCountIs('AWS::CloudFront::Distribution', 1);
    template.resourceCountIs('AWS::CloudFront::ResponseHeadersPolicy', 1);
    template.resourceCountIs('AWS::CloudFront::OriginAccessControl', 1);
  });
});
