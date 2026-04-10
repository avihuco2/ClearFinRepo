// Property-based tests for pipeline helper functions
// Feature: github-actions-deployment

import { describe, it, expect } from 'vitest';
import * as fc from 'fast-check';
import { buildOidcTrustPolicy, extractArtifactSummary, getCacheControlHeader, formatDeploymentSummary, isValidActionShaPin, buildImageTag } from './pipeline-helpers.js';

// ── Generators ───────────────────────────────────────────────────────

/** Generator for valid environment names. */
const envArb = fc.constantFrom('dev', 'staging', 'prod');

/** Generator for AWS account IDs (12-digit numeric strings). */
const accountIdArb = fc.stringOf(fc.constantFrom(...'0123456789'.split('')), {
  minLength: 12,
  maxLength: 12,
});

/** Generator for GitHub org names (alphanumeric + hyphens, non-empty). */
const orgArb = fc.stringOf(
  fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz0123456789-'.split('')),
  { minLength: 1, maxLength: 40 },
);

/** Generator for GitHub repo names (alphanumeric + hyphens + dots + underscores, non-empty). */
const repoArb = fc.stringOf(
  fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz0123456789-._'.split('')),
  { minLength: 1, maxLength: 100 },
);

// ── Expected branch restrictions per environment ─────────────────────

const EXPECTED_BRANCHES: Record<string, string[]> = {
  dev: ['main', 'develop'],
  staging: ['main'],
  prod: ['main'],
};

// ── Property 1: OIDC Trust Policy Branch Restrictions ────────────────
// **Validates: Requirements 1.3**

describe('Feature: github-actions-deployment, Property 1: OIDC trust policy branch restrictions', () => {
  it('generates trust policies with exactly the correct branch conditions per environment', () => {
    fc.assert(
      fc.property(envArb, accountIdArb, orgArb, repoArb, (env, accountId, org, repo) => {
        const policy = buildOidcTrustPolicy(env, accountId, org, repo);
        const expectedBranches = EXPECTED_BRANCHES[env];
        const expectedSubs = expectedBranches.map(
          (branch) => `repo:${org}/${repo}:ref:refs/heads/${branch}`,
        );

        const sub =
          policy.Statement[0].Condition.StringLike['token.actions.githubusercontent.com:sub'];

        // dev has multiple branches → array; staging/prod have one → string
        if (expectedBranches.length === 1) {
          expect(sub).toBe(expectedSubs[0]);
        } else {
          expect(sub).toEqual(expectedSubs);
        }
      }),
      { numRuns: 100 },
    );
  });

  it('dev allows exactly main and develop — no more, no fewer', () => {
    fc.assert(
      fc.property(accountIdArb, orgArb, repoArb, (accountId, org, repo) => {
        const policy = buildOidcTrustPolicy('dev', accountId, org, repo);
        const sub =
          policy.Statement[0].Condition.StringLike['token.actions.githubusercontent.com:sub'];

        const subs = Array.isArray(sub) ? sub : [sub];
        expect(subs).toHaveLength(2);
        expect(subs).toContain(`repo:${org}/${repo}:ref:refs/heads/main`);
        expect(subs).toContain(`repo:${org}/${repo}:ref:refs/heads/develop`);
      }),
      { numRuns: 100 },
    );
  });

  it('staging allows exactly main only', () => {
    fc.assert(
      fc.property(accountIdArb, orgArb, repoArb, (accountId, org, repo) => {
        const policy = buildOidcTrustPolicy('staging', accountId, org, repo);
        const sub =
          policy.Statement[0].Condition.StringLike['token.actions.githubusercontent.com:sub'];

        expect(sub).toBe(`repo:${org}/${repo}:ref:refs/heads/main`);
      }),
      { numRuns: 100 },
    );
  });

  it('prod allows exactly main only', () => {
    fc.assert(
      fc.property(accountIdArb, orgArb, repoArb, (accountId, org, repo) => {
        const policy = buildOidcTrustPolicy('prod', accountId, org, repo);
        const sub =
          policy.Statement[0].Condition.StringLike['token.actions.githubusercontent.com:sub'];

        expect(sub).toBe(`repo:${org}/${repo}:ref:refs/heads/main`);
      }),
      { numRuns: 100 },
    );
  });

  it('always sets the correct OIDC provider ARN for any valid inputs', () => {
    fc.assert(
      fc.property(envArb, accountIdArb, orgArb, repoArb, (env, accountId, org, repo) => {
        const policy = buildOidcTrustPolicy(env, accountId, org, repo);

        expect(policy.Statement[0].Principal.Federated).toBe(
          `arn:aws:iam::${accountId}:oidc-provider/token.actions.githubusercontent.com`,
        );
        expect(policy.Statement[0].Condition.StringEquals['token.actions.githubusercontent.com:aud']).toBe(
          'sts.amazonaws.com',
        );
        expect(policy.Statement[0].Action).toBe('sts:AssumeRoleWithWebIdentity');
        expect(policy.Version).toBe('2012-10-17');
      }),
      { numRuns: 100 },
    );
  });
});

// ── Property 2: Artifact Bundle Summary Extraction ───────────────────
// **Validates: Requirements 5.3**

/** All CloudFormation resource types relevant to artifact summary extraction. */
const IAM_TYPES = ['AWS::IAM::Policy', 'AWS::IAM::ManagedPolicy', 'AWS::IAM::Role'] as const;
const STS_TYPES = ['AWS::IAM::Role', 'AWS::STS::AssumeRole'] as const;
const SM_TYPES = ['AWS::SecretsManager::Secret', 'AWS::SecretsManager::ResourcePolicy'] as const;
const ALL_RELEVANT_TYPES = [...new Set([...IAM_TYPES, ...STS_TYPES, ...SM_TYPES])];

/** Generator for a logical resource ID (alphanumeric, non-empty). */
const logicalIdArb = fc.stringOf(
  fc.constantFrom(...'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'.split('')),
  { minLength: 1, maxLength: 30 },
);

/** Generator for a relevant CFN resource type. */
const relevantTypeArb = fc.constantFrom(...ALL_RELEVANT_TYPES);

/** Generator for an irrelevant CFN resource type (not in any category). */
const irrelevantTypeArb = fc.constantFrom(
  'AWS::EC2::Instance',
  'AWS::S3::Bucket',
  'AWS::Lambda::Function',
  'AWS::DynamoDB::Table',
  'AWS::SNS::Topic',
);

/** Generator for a single CFN resource entry. */
const cfnResourceArb = fc.oneof(
  relevantTypeArb.map((type) => ({ type, relevant: true as const })),
  irrelevantTypeArb.map((type) => ({ type, relevant: false as const })),
);

/** Generator for a CFN template with a random set of resources. */
const cfnTemplateArb = fc
  .array(fc.tuple(logicalIdArb, cfnResourceArb), { minLength: 0, maxLength: 10 })
  .map((entries) => {
    const resources: Record<string, { Type: string; Properties?: Record<string, unknown> }> = {};
    for (const [id, { type }] of entries) {
      resources[id] = { Type: type };
    }
    return { Resources: resources };
  });

/** Generator for an array of CFN templates. */
const cfnTemplatesArb = fc.array(cfnTemplateArb, { minLength: 0, maxLength: 5 });

describe('Feature: github-actions-deployment, Property 2: Artifact bundle summary extraction', () => {
  it('extracts every IAM/STS/SM policy from any set of CloudFormation templates', () => {
    fc.assert(
      fc.property(cfnTemplatesArb, (templates) => {
        const summary = extractArtifactSummary(templates);

        // Manually compute expected results from the templates
        const expectedIam: string[] = [];
        const expectedSts: string[] = [];
        const expectedSm: string[] = [];

        for (const tpl of templates) {
          for (const [logicalId, resource] of Object.entries(tpl.Resources ?? {})) {
            const t = resource.Type;
            if (IAM_TYPES.includes(t as typeof IAM_TYPES[number])) expectedIam.push(logicalId);
            if (STS_TYPES.includes(t as typeof STS_TYPES[number])) expectedSts.push(logicalId);
            if (SM_TYPES.includes(t as typeof SM_TYPES[number])) expectedSm.push(logicalId);
          }
        }

        expect(summary.iamPolicies).toEqual(expectedIam);
        expect(summary.stsTrustPolicies).toEqual(expectedSts);
        expect(summary.secretsManagerPolicies).toEqual(expectedSm);
      }),
      { numRuns: 100 },
    );
  });

  it('reports a component as missing if and only if no policies of that type exist', () => {
    fc.assert(
      fc.property(cfnTemplatesArb, (templates) => {
        const summary = extractArtifactSummary(templates);

        const hasIam = summary.iamPolicies.length > 0;
        const hasSts = summary.stsTrustPolicies.length > 0;
        const hasSm = summary.secretsManagerPolicies.length > 0;

        if (!hasIam) {
          expect(summary.missingComponents).toContain('iam-policy-documents');
        } else {
          expect(summary.missingComponents).not.toContain('iam-policy-documents');
        }

        if (!hasSts) {
          expect(summary.missingComponents).toContain('sts-trust-policies');
        } else {
          expect(summary.missingComponents).not.toContain('sts-trust-policies');
        }

        if (!hasSm) {
          expect(summary.missingComponents).toContain('secrets-manager-resource-policies');
        } else {
          expect(summary.missingComponents).not.toContain('secrets-manager-resource-policies');
        }
      }),
      { numRuns: 100 },
    );
  });

  it('returns empty arrays and all three missing components for empty template sets', () => {
    fc.assert(
      fc.property(fc.constant([]), (templates) => {
        const summary = extractArtifactSummary(templates);

        expect(summary.iamPolicies).toEqual([]);
        expect(summary.stsTrustPolicies).toEqual([]);
        expect(summary.secretsManagerPolicies).toEqual([]);
        expect(summary.missingComponents).toEqual([
          'iam-policy-documents',
          'sts-trust-policies',
          'secrets-manager-resource-policies',
        ]);
      }),
      { numRuns: 100 },
    );
  });
});

// ── Property 3: Cache-Control Header Selection ───────────────────────
// **Validates: Requirements 6.3**

/** Generator for file extensions commonly found in web builds. */
const extensionArb = fc.constantFrom(
  '.js', '.css', '.html', '.json', '.svg', '.png', '.jpg', '.woff2', '.map', '.ico', '.txt',
);

/** Generator for content-hash segments (hex strings mimicking bundler output). */
const hashSegmentArb = fc.stringOf(
  fc.constantFrom(...'0123456789abcdef'.split('')),
  { minLength: 6, maxLength: 12 },
);

/** Generator for a base filename part (alphanumeric, non-empty). */
const baseNameArb = fc.stringOf(
  fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz'.split('')),
  { minLength: 1, maxLength: 20 },
);

/** Generator for optional directory prefixes. */
const dirPrefixArb = fc.constantFrom('', 'assets/', 'static/', 'js/', 'css/', 'img/');

/** Generator for a hashed asset filename (e.g. `assets/app.a1b2c3d4.js`). */
const hashedFilenameArb = fc.tuple(dirPrefixArb, baseNameArb, hashSegmentArb, extensionArb).map(
  ([dir, base, hash, ext]) => `${dir}${base}.${hash}${ext}`,
);

/** Generator for a plain (non-hashed) filename that is NOT index.html. */
const plainFilenameArb = fc.tuple(dirPrefixArb, baseNameArb, extensionArb)
  .filter(([_dir, base, ext]) => !(base === 'index' && ext === '.html'))
  .map(([dir, base, ext]) => `${dir}${base}${ext}`);

/** Generator for index.html with optional directory prefix. */
const indexHtmlArb = dirPrefixArb.map((dir) => `${dir}index.html`);

/** Generator for any filename (hashed, plain, or index.html). */
const anyFilenameArb = fc.oneof(hashedFilenameArb, plainFilenameArb, indexHtmlArb);

describe('Feature: github-actions-deployment, Property 3: Cache-Control header selection', () => {
  it('returns no-cache for any path ending in index.html', () => {
    fc.assert(
      fc.property(indexHtmlArb, (filename) => {
        const header = getCacheControlHeader(filename);
        expect(header).toBe('no-cache');
      }),
      { numRuns: 100 },
    );
  });

  it('returns max-age=31536000, immutable for hashed asset filenames', () => {
    fc.assert(
      fc.property(hashedFilenameArb, (filename) => {
        const header = getCacheControlHeader(filename);
        expect(header).toBe('max-age=31536000, immutable');
      }),
      { numRuns: 100 },
    );
  });

  it('returns max-age=31536000, immutable for plain filenames that are not index.html', () => {
    fc.assert(
      fc.property(plainFilenameArb, (filename) => {
        const header = getCacheControlHeader(filename);
        expect(header).toBe('max-age=31536000, immutable');
      }),
      { numRuns: 100 },
    );
  });

  it('never returns undefined or empty string for any filename', () => {
    fc.assert(
      fc.property(anyFilenameArb, (filename) => {
        const header = getCacheControlHeader(filename);
        expect(header).toBeDefined();
        expect(header).not.toBe('');
        expect(typeof header).toBe('string');
      }),
      { numRuns: 100 },
    );
  });

  it('always returns one of exactly two valid cache-control values', () => {
    fc.assert(
      fc.property(anyFilenameArb, (filename) => {
        const header = getCacheControlHeader(filename);
        const validValues = ['no-cache', 'max-age=31536000, immutable'];
        expect(validValues).toContain(header);
      }),
      { numRuns: 100 },
    );
  });
});

// ── Property 4: Deployment Summary Completeness ──────────────────────
// **Validates: Requirements 9.4**

/** Generator for 40-char hex git SHAs. */
const gitShaArb = fc.stringOf(
  fc.constantFrom(...'0123456789abcdef'.split('')),
  { minLength: 40, maxLength: 40 },
);

/** Generator for Docker image tag maps (service name → tag). */
const dockerImageTagsArb = fc.dictionary(
  fc.stringOf(fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz-'.split('')), { minLength: 1, maxLength: 20 }),
  fc.stringOf(fc.constantFrom(...'0123456789abcdef'.split('')), { minLength: 7, maxLength: 12 }),
  { minKeys: 1, maxKeys: 5 },
);

/** Generator for CDK stack name lists. */
const cdkStacksArb = fc.array(
  fc.stringOf(fc.constantFrom(...'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-'.split('')), { minLength: 1, maxLength: 30 }),
  { minLength: 1, maxLength: 6 },
);

/** Generator for sentinel approval statuses. */
const sentinelStatusArb = fc.constantFrom('approved' as const, 'not-required' as const, 'rejected' as const, 'timeout' as const);

/** Generator for deployment duration in seconds. */
const durationArb = fc.nat({ max: 36000 });

/** Generator for environment names. */
const deployEnvArb = fc.constantFrom('dev', 'staging', 'prod');

/** Generator for a complete DeploymentSummaryInput. */
const deploymentSummaryInputArb = fc.record({
  gitCommitSha: gitShaArb,
  dockerImageTags: dockerImageTagsArb,
  cdkStacksDeployed: cdkStacksArb,
  sentinelApprovalStatus: sentinelStatusArb,
  deploymentDuration: durationArb,
  environment: deployEnvArb,
  timestamp: fc.date(),
});

describe('Feature: github-actions-deployment, Property 4: Deployment summary completeness', () => {
  it('summary contains the git commit SHA', () => {
    fc.assert(
      fc.property(deploymentSummaryInputArb, (input) => {
        const summary = formatDeploymentSummary(input);
        expect(summary).toContain(input.gitCommitSha);
      }),
      { numRuns: 100 },
    );
  });

  it('summary contains every Docker image tag', () => {
    fc.assert(
      fc.property(deploymentSummaryInputArb, (input) => {
        const summary = formatDeploymentSummary(input);
        for (const [service, tag] of Object.entries(input.dockerImageTags)) {
          expect(summary).toContain(service);
          expect(summary).toContain(tag);
        }
      }),
      { numRuns: 100 },
    );
  });

  it('summary contains every CDK stack name', () => {
    fc.assert(
      fc.property(deploymentSummaryInputArb, (input) => {
        const summary = formatDeploymentSummary(input);
        for (const stack of input.cdkStacksDeployed) {
          expect(summary).toContain(stack);
        }
      }),
      { numRuns: 100 },
    );
  });

  it('summary contains the sentinel approval status', () => {
    fc.assert(
      fc.property(deploymentSummaryInputArb, (input) => {
        const summary = formatDeploymentSummary(input);
        expect(summary).toContain(input.sentinelApprovalStatus);
      }),
      { numRuns: 100 },
    );
  });

  it('summary contains the deployment duration', () => {
    fc.assert(
      fc.property(deploymentSummaryInputArb, (input) => {
        const summary = formatDeploymentSummary(input);
        expect(summary).toContain(String(input.deploymentDuration));
      }),
      { numRuns: 100 },
    );
  });

  it('no required field is absent from the output for any valid input', () => {
    fc.assert(
      fc.property(deploymentSummaryInputArb, (input) => {
        const summary = formatDeploymentSummary(input);

        // Git SHA present
        expect(summary).toContain(input.gitCommitSha);

        // All image tags present
        for (const [service, tag] of Object.entries(input.dockerImageTags)) {
          expect(summary).toContain(service);
          expect(summary).toContain(tag);
        }

        // All stack names present
        for (const stack of input.cdkStacksDeployed) {
          expect(summary).toContain(stack);
        }

        // Sentinel status present
        expect(summary).toContain(input.sentinelApprovalStatus);

        // Duration present
        expect(summary).toContain(String(input.deploymentDuration));
      }),
      { numRuns: 100 },
    );
  });
});

// ── Property 5: Third-Party Action SHA Pinning ───────────────────────
// **Validates: Requirements 9.1**

/** Generator for a valid 40-char lowercase hex SHA. */
const sha40Arb = fc.stringOf(
  fc.constantFrom(...'0123456789abcdef'.split('')),
  { minLength: 40, maxLength: 40 },
);

/** Generator for GitHub org/action owner names. */
const actionOwnerArb = fc.stringOf(
  fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz0123456789-'.split('')),
  { minLength: 1, maxLength: 30 },
);

/** Generator for GitHub action repo names. */
const actionRepoArb = fc.stringOf(
  fc.constantFrom(...'abcdefghijklmnopqrstuvwxyz0123456789-_.'.split('')),
  { minLength: 1, maxLength: 40 },
);

/** Generator for a valid SHA-pinned action reference (e.g. `owner/repo@<40-hex>`). */
const validShaPinnedRefArb = fc.tuple(actionOwnerArb, actionRepoArb, sha40Arb).map(
  ([owner, repo, sha]) => `${owner}/${repo}@${sha}`,
);

/** Generator for mutable tag versions (not valid SHA pins). */
const mutableTagArb = fc.oneof(
  // Semver-style tags: v1, v2.3, v4.1.0
  fc.nat({ max: 20 }).map((n) => `v${n}`),
  fc.tuple(fc.nat({ max: 20 }), fc.nat({ max: 20 })).map(([a, b]) => `v${a}.${b}`),
  // Named tags
  fc.constantFrom('latest', 'main', 'master', 'stable', 'release', 'nightly'),
  // Short SHAs (< 40 chars hex)
  fc.stringOf(fc.constantFrom(...'0123456789abcdef'.split('')), { minLength: 1, maxLength: 39 }),
  // Uppercase hex (40 chars but not lowercase)
  fc.stringOf(fc.constantFrom(...'0123456789ABCDEF'.split('')), { minLength: 40, maxLength: 40 })
    .filter((s) => s !== s.toLowerCase()),
);

/** Generator for an invalid (mutable-tag) action reference. */
const invalidRefArb = fc.tuple(actionOwnerArb, actionRepoArb, mutableTagArb).map(
  ([owner, repo, tag]) => `${owner}/${repo}@${tag}`,
);

/** Generator for references missing the @ separator entirely. */
const noAtRefArb = fc.tuple(actionOwnerArb, actionRepoArb).map(
  ([owner, repo]) => `${owner}/${repo}`,
);

describe('Feature: github-actions-deployment, Property 5: Third-party action SHA pinning', () => {
  it('accepts any action reference pinned to a valid 40-char lowercase hex SHA', () => {
    fc.assert(
      fc.property(validShaPinnedRefArb, (ref) => {
        expect(isValidActionShaPin(ref)).toBe(true);
      }),
      { numRuns: 100 },
    );
  });

  it('rejects action references using mutable tags instead of SHA pins', () => {
    fc.assert(
      fc.property(invalidRefArb, (ref) => {
        expect(isValidActionShaPin(ref)).toBe(false);
      }),
      { numRuns: 100 },
    );
  });

  it('rejects action references with no @ separator', () => {
    fc.assert(
      fc.property(noAtRefArb, (ref) => {
        expect(isValidActionShaPin(ref)).toBe(false);
      }),
      { numRuns: 100 },
    );
  });

  it('the version part after @ is exactly 40 lowercase hex characters for valid pins', () => {
    fc.assert(
      fc.property(validShaPinnedRefArb, (ref) => {
        const version = ref.slice(ref.lastIndexOf('@') + 1);
        expect(version).toHaveLength(40);
        expect(version).toMatch(/^[0-9a-f]{40}$/);
        expect(isValidActionShaPin(ref)).toBe(true);
      }),
      { numRuns: 100 },
    );
  });

  it('rejects 40-char hex strings that contain uppercase characters', () => {
    fc.assert(
      fc.property(
        actionOwnerArb,
        actionRepoArb,
        fc.stringOf(fc.constantFrom(...'0123456789ABCDEF'.split('')), { minLength: 40, maxLength: 40 })
          .filter((s) => s !== s.toLowerCase()),
        (owner, repo, upperSha) => {
          const ref = `${owner}/${repo}@${upperSha}`;
          expect(isValidActionShaPin(ref)).toBe(false);
        },
      ),
      { numRuns: 100 },
    );
  });
});


// ── Property 6: Image Tag Consistency Across Environments ────────────
// **Validates: Requirements 7.5**

/** Generator for 40-char hex git SHAs (simulating real commit hashes). */
const gitShaForTagArb = fc.stringOf(
  fc.constantFrom(...'0123456789abcdef'.split('')),
  { minLength: 40, maxLength: 40 },
);

/** Generator for a list of environment names (simulating deploy jobs in a single workflow run). */
const envListArb = fc.array(
  fc.constantFrom('dev', 'staging', 'prod'),
  { minLength: 1, maxLength: 10 },
);

describe('Feature: github-actions-deployment, Property 6: Image tag consistency across environments', () => {
  it('all deploy jobs within a single workflow run produce the same image tag from the same git SHA', () => {
    fc.assert(
      fc.property(gitShaForTagArb, envListArb, (gitSha, environments) => {
        const tags = environments.map(() => buildImageTag(gitSha));
        const uniqueTags = new Set(tags);
        expect(uniqueTags.size).toBe(1);
      }),
      { numRuns: 100 },
    );
  });

  it('the image tag used for ECR push equals the image tag used in CDK context for every deploy job', () => {
    fc.assert(
      fc.property(gitShaForTagArb, envListArb, (gitSha, environments) => {
        // Simulate: ECR push step computes the tag once
        const ecrPushTag = buildImageTag(gitSha);

        // Simulate: each deploy job computes the tag independently for CDK context
        for (const _env of environments) {
          const cdkContextTag = buildImageTag(gitSha);
          expect(cdkContextTag).toBe(ecrPushTag);
        }
      }),
      { numRuns: 100 },
    );
  });

  it('the image tag is always a prefix of the original git SHA', () => {
    fc.assert(
      fc.property(gitShaForTagArb, (gitSha) => {
        const tag = buildImageTag(gitSha);
        expect(gitSha.startsWith(tag)).toBe(true);
      }),
      { numRuns: 100 },
    );
  });

  it('the image tag is exactly 7 characters for any valid 40-char SHA', () => {
    fc.assert(
      fc.property(gitShaForTagArb, (gitSha) => {
        const tag = buildImageTag(gitSha);
        expect(tag).toHaveLength(7);
      }),
      { numRuns: 100 },
    );
  });

  it('different git SHAs with different first 7 chars produce different image tags', () => {
    fc.assert(
      fc.property(gitShaForTagArb, gitShaForTagArb, (sha1, sha2) => {
        fc.pre(sha1.slice(0, 7) !== sha2.slice(0, 7));
        expect(buildImageTag(sha1)).not.toBe(buildImageTag(sha2));
      }),
      { numRuns: 100 },
    );
  });
});
