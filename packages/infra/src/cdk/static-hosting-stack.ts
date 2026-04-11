// @clearfin/infra — StaticHostingCdkStack: S3 bucket + CloudFront distribution for Login Page SPA
// Validates: Requirements 7.1, 7.2, 7.3, 7.4, 7.5, 7.6

import * as cdk from 'aws-cdk-lib';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import { Construct } from 'constructs';
import type { CloudFrontConfig } from '../cloudfront.js';

export interface StaticHostingCdkStackProps extends cdk.StackProps {
  clearfinEnv: string;
  cloudFrontConfig: CloudFrontConfig;
  albDnsName?: string;
}

export class StaticHostingCdkStack extends cdk.Stack {
  public readonly bucket: s3.Bucket;
  public readonly distribution: cloudfront.Distribution;

  constructor(scope: Construct, id: string, props: StaticHostingCdkStackProps) {
    super(scope, id, props);

    const { cloudFrontConfig } = props;
    const { s3Bucket: bucketCfg, distribution: distCfg } = cloudFrontConfig;

    // Req 7.6: Apply tags from S3 bucket config
    for (const [key, value] of Object.entries(bucketCfg.tags)) {
      cdk.Tags.of(this).add(key, value);
    }
    // Req 7.6: Apply tags from distribution config
    for (const [key, value] of Object.entries(distCfg.tags)) {
      cdk.Tags.of(this).add(key, value);
    }

    // ─── S3 Bucket ─────────────────────────────────────────────────────
    // Req 7.1: S3 bucket with all public access blocked, AES-256 encryption, versioning
    this.bucket = new s3.Bucket(this, 'LoginPageBucket', {
      bucketName: `${bucketCfg.name}-assets`,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      versioned: bucketCfg.versioning,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
    });

    // Apply per-bucket tags
    for (const [key, value] of Object.entries(bucketCfg.tags)) {
      cdk.Tags.of(this.bucket).add(key, value);
    }

    // ─── Response Headers Policy ───────────────────────────────────────
    // Req 7.4: Response headers policy with security headers
    const secHeaders = distCfg.responseHeadersPolicy.securityHeaders;

    const responseHeadersPolicy = new cloudfront.ResponseHeadersPolicy(this, 'SecurityHeadersPolicy', {
      responseHeadersPolicyName: distCfg.responseHeadersPolicy.name,
      securityHeadersBehavior: {
        contentSecurityPolicy: {
          contentSecurityPolicy: secHeaders.contentSecurityPolicy,
          override: true,
        },
        strictTransportSecurity: {
          accessControlMaxAge: cdk.Duration.seconds(
            parseInt(secHeaders.strictTransportSecurity.match(/max-age=(\d+)/)?.[1] ?? '31536000', 10),
          ),
          includeSubdomains: secHeaders.strictTransportSecurity.includes('includeSubDomains'),
          override: true,
        },
        contentTypeOptions: {
          override: true,
        },
        frameOptions: {
          frameOption: cloudfront.HeadersFrameOption.DENY,
          override: true,
        },
        xssProtection: {
          protection: true,
          modeBlock: true,
          override: true,
        },
        referrerPolicy: {
          referrerPolicy: cloudfront.HeadersReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN,
          override: true,
        },
      },
    });

    // ─── CloudFront Distribution ───────────────────────────────────────
    // Req 7.2: CloudFront distribution with OAC (SigV4 signing) to access S3 bucket
    // Req 7.3: redirect-to-https, HTTP/2 and HTTP/3, index.html default root object
    // Req 7.5: Custom error responses for 403 and 404 (SPA routing)
    this.distribution = new cloudfront.Distribution(this, 'LoginDistribution', {
      comment: distCfg.name,
      enabled: distCfg.enabled,
      defaultRootObject: distCfg.defaultRootObject,
      httpVersion: cloudfront.HttpVersion.HTTP2_AND_3,
      priceClass: cloudfront.PriceClass.PRICE_CLASS_100,
      defaultBehavior: {
        origin: origins.S3BucketOrigin.withOriginAccessControl(this.bucket),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        responseHeadersPolicy,
      },
      errorResponses: distCfg.errorResponses.map((errCfg) => ({
        httpStatus: errCfg.httpStatus,
        responsePagePath: errCfg.responsePagePath,
        responseHttpStatus: errCfg.responseHttpStatus,
        ttl: cdk.Duration.seconds(errCfg.ttlSeconds),
      })),
    });

    // Apply per-distribution tags
    for (const [key, value] of Object.entries(distCfg.tags)) {
      cdk.Tags.of(this.distribution).add(key, value);
    }

    // ─── ALB Origin for /auth/* ────────────────────────────────────────
    // Req 3.1: ALB origin with HTTPS-only protocol policy
    // Req 3.2: /auth/* cache behavior with CachingDisabled
    // Req 3.3: AllViewerExceptHostHeader forwards query strings + cookies
    // Req 3.5: HTTPS-only origin protocol policy
    if (props.albDnsName) {
      const albOrigin = new origins.HttpOrigin(props.albDnsName, {
        protocolPolicy: cloudfront.OriginProtocolPolicy.HTTPS_ONLY,
      });

      this.distribution.addBehavior('/auth/*', albOrigin, {
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        cachePolicy: cloudfront.CachePolicy.CACHING_DISABLED,
        originRequestPolicy: cloudfront.OriginRequestPolicy.ALL_VIEWER_EXCEPT_HOST_HEADER,
        allowedMethods: cloudfront.AllowedMethods.ALLOW_ALL,
      });
    }
  }
}
