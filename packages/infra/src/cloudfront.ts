// @clearfin/infra — CloudFront distribution and S3 bucket for Login_Page
// Validates: Requirements 8.6

export interface S3BucketConfig {
  name: string;
  blockPublicAccess: {
    blockPublicAcls: boolean;
    blockPublicPolicy: boolean;
    ignorePublicAcls: boolean;
    restrictPublicBuckets: boolean;
  };
  encryption: {
    type: 'AES256';
  };
  versioning: boolean;
  tags: Record<string, string>;
}

export interface ResponseHeadersPolicyConfig {
  name: string;
  securityHeaders: {
    contentSecurityPolicy: string;
    strictTransportSecurity: string;
    contentTypeOptions: boolean;
    frameOptions: 'DENY';
    xssProtection: boolean;
    referrerPolicy: 'strict-origin-when-cross-origin';
  };
}

export interface CloudFrontDistributionConfig {
  name: string;
  enabled: boolean;
  defaultRootObject: string;
  httpVersion: 'http2and3';
  priceClass: string;
  viewerProtocolPolicy: 'redirect-to-https';
  originAccessControl: {
    name: string;
    signingProtocol: 'sigv4';
    signingBehavior: 'always';
    originType: 's3';
  };
  s3Origin: {
    bucketName: string;
  };
  responseHeadersPolicy: ResponseHeadersPolicyConfig;
  errorResponses: Array<{
    httpStatus: number;
    responsePagePath: string;
    responseHttpStatus: number;
    ttlSeconds: number;
  }>;
  tags: Record<string, string>;
}

export interface CloudFrontConfig {
  s3Bucket: S3BucketConfig;
  distribution: CloudFrontDistributionConfig;
}

export function buildCloudFrontConfig(env: string, appOrigin: string): CloudFrontConfig {
  const bucketName = `clearfin-${env}-login-page`;

  const s3Bucket: S3BucketConfig = {
    name: bucketName,
    blockPublicAccess: {
      blockPublicAcls: true,
      blockPublicPolicy: true,
      ignorePublicAcls: true,
      restrictPublicBuckets: true,
    },
    encryption: { type: 'AES256' as const },
    versioning: true,
    tags: {
      Project: 'ClearFin',
      Environment: env,
      Component: 'login-page',
    },
  };

  const responseHeadersPolicy: ResponseHeadersPolicyConfig = {
    name: `clearfin-${env}-login-headers`,
    securityHeaders: {
      contentSecurityPolicy: `default-src 'self'; script-src '${appOrigin}'; style-src '${appOrigin}' 'unsafe-inline'; img-src '${appOrigin}' data:; connect-src '${appOrigin}'; frame-ancestors 'none'`,
      strictTransportSecurity: 'max-age=31536000; includeSubDomains',
      contentTypeOptions: true,
      frameOptions: 'DENY' as const,
      xssProtection: true,
      referrerPolicy: 'strict-origin-when-cross-origin' as const,
    },
  };

  return {
    s3Bucket,
    distribution: {
      name: `clearfin-${env}-login-distribution`,
      enabled: true,
      defaultRootObject: 'index.html',
      httpVersion: 'http2and3' as const,
      priceClass: 'PriceClass_100',
      viewerProtocolPolicy: 'redirect-to-https' as const,
      originAccessControl: {
        name: `clearfin-${env}-login-oac`,
        signingProtocol: 'sigv4' as const,
        signingBehavior: 'always' as const,
        originType: 's3' as const,
      },
      s3Origin: { bucketName },
      responseHeadersPolicy,
      errorResponses: [
        { httpStatus: 403, responsePagePath: '/index.html', responseHttpStatus: 200, ttlSeconds: 300 },
        { httpStatus: 404, responsePagePath: '/index.html', responseHttpStatus: 200, ttlSeconds: 300 },
      ],
      tags: {
        Project: 'ClearFin',
        Environment: env,
        Component: 'cdn',
      },
    },
  };
}
