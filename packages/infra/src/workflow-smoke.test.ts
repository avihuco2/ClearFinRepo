import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { isValidActionShaPin } from './pipeline-helpers.js';

// ── Helpers ──────────────────────────────────────────────────────────

const ROOT = resolve(__dirname, '..', '..', '..');

function readWorkflow(name: string): string {
  return readFileSync(resolve(ROOT, '.github', 'workflows', name), 'utf-8');
}

/**
 * Extract all `uses:` references from a workflow YAML string.
 * Returns entries like "actions/checkout@abc123..." or "docker/build-push-action@def456..."
 */
function extractUsesRefs(yaml: string): string[] {
  const refs: string[] = [];
  for (const line of yaml.split('\n')) {
    const match = line.match(/^\s*uses:\s*(.+)$/);
    if (match) {
      // Strip inline YAML comments (e.g., "actions/checkout@sha # v4")
      const raw = match[1].trim();
      const commentIndex = raw.indexOf(' #');
      const ref = commentIndex !== -1 ? raw.slice(0, commentIndex).trim() : raw;
      refs.push(ref);
    }
  }
  return refs;
}

/**
 * Extract all job names from a workflow YAML string.
 * Looks for top-level keys under `jobs:`.
 */
function extractJobNames(yaml: string): string[] {
  const jobs: string[] = [];
  const lines = yaml.split('\n');
  let inJobs = false;
  for (const line of lines) {
    if (/^jobs:\s*$/.test(line)) {
      inJobs = true;
      continue;
    }
    if (inJobs) {
      // A job name is a key at 2-space indent under jobs:
      const jobMatch = line.match(/^  ([a-z][a-z0-9_-]*):\s*$/);
      if (jobMatch) {
        jobs.push(jobMatch[1]);
      }
      // If we hit a non-indented line that isn't blank, we left the jobs block
      if (/^\S/.test(line) && line.trim() !== '') {
        inJobs = false;
      }
    }
  }
  return jobs;
}

/**
 * Check if a job block contains a `permissions:` key.
 */
function jobHasPermissions(yaml: string, jobName: string): boolean {
  const lines = yaml.split('\n');
  let inTargetJob = false;
  for (const line of lines) {
    // Detect job start (2-space indent key under jobs:)
    if (new RegExp(`^  ${jobName}:\\s*$`).test(line)) {
      inTargetJob = true;
      continue;
    }
    if (inTargetJob) {
      // Another job at same indent level means we left the target job
      if (/^  [a-z][a-z0-9_-]*:\s*$/.test(line) && !new RegExp(`^  ${jobName}:`).test(line)) {
        return false;
      }
      // permissions at 4-space indent (direct child of job)
      if (/^    permissions:\s*$/.test(line) || /^    permissions:/.test(line)) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Check if a job references a specific GitHub environment.
 */
function jobHasEnvironment(yaml: string, jobName: string, envName: string): boolean {
  const lines = yaml.split('\n');
  let inTargetJob = false;
  for (const line of lines) {
    if (new RegExp(`^  ${jobName}:\\s*$`).test(line)) {
      inTargetJob = true;
      continue;
    }
    if (inTargetJob) {
      if (/^  [a-z][a-z0-9_-]*:\s*$/.test(line) && !new RegExp(`^  ${jobName}:`).test(line)) {
        return false;
      }
      if (line.match(new RegExp(`^    environment:\\s*${envName}\\s*$`))) {
        return true;
      }
    }
  }
  return false;
}

// ── Tests ────────────────────────────────────────────────────────────

const deployYaml = readWorkflow('deploy.yml');
const bootstrapYaml = readWorkflow('bootstrap.yml');

describe('Workflow smoke tests (Req 9.1, 9.2, 9.3)', () => {
  // ── Third-party action SHA pinning (Req 9.1) ───────────────────────

  describe('third-party actions are pinned to commit SHAs', () => {
    it('deploy.yml: all uses references are SHA-pinned', () => {
      const refs = extractUsesRefs(deployYaml);
      expect(refs.length).toBeGreaterThan(0);

      for (const ref of refs) {
        // Skip local actions (e.g., ./.github/actions/foo)
        if (ref.startsWith('./') || ref.startsWith('.\\')) continue;

        expect(
          isValidActionShaPin(ref),
          `Action "${ref}" is not pinned to a 40-char commit SHA`,
        ).toBe(true);
      }
    });

    it('bootstrap.yml: all uses references are SHA-pinned', () => {
      const refs = extractUsesRefs(bootstrapYaml);
      expect(refs.length).toBeGreaterThan(0);

      for (const ref of refs) {
        if (ref.startsWith('./') || ref.startsWith('.\\')) continue;

        expect(
          isValidActionShaPin(ref),
          `Action "${ref}" is not pinned to a 40-char commit SHA`,
        ).toBe(true);
      }
    });
  });

  // ── Explicit permissions blocks (Req 9.2) ──────────────────────────

  describe('each job has an explicit permissions block', () => {
    it('deploy.yml: every job declares permissions', () => {
      const jobs = extractJobNames(deployYaml);
      expect(jobs.length).toBeGreaterThan(0);

      for (const job of jobs) {
        expect(
          jobHasPermissions(deployYaml, job),
          `Job "${job}" in deploy.yml is missing a permissions block`,
        ).toBe(true);
      }
    });

    it('bootstrap.yml: every job declares permissions', () => {
      const jobs = extractJobNames(bootstrapYaml);
      expect(jobs.length).toBeGreaterThan(0);

      for (const job of jobs) {
        expect(
          jobHasPermissions(bootstrapYaml, job),
          `Job "${job}" in bootstrap.yml is missing a permissions block`,
        ).toBe(true);
      }
    });
  });

  // ── Deploy jobs reference correct environments ─────────────────────

  describe('deploy jobs reference correct GitHub environments', () => {
    it('deploy-dev references dev environment', () => {
      expect(jobHasEnvironment(deployYaml, 'deploy-dev', 'dev')).toBe(true);
    });

    it('deploy-staging references staging environment', () => {
      expect(jobHasEnvironment(deployYaml, 'deploy-staging', 'staging')).toBe(true);
    });

    it('deploy-prod references prod environment', () => {
      expect(jobHasEnvironment(deployYaml, 'deploy-prod', 'prod')).toBe(true);
    });
  });

  // ── Bootstrap workflow structure ───────────────────────────────────

  describe('bootstrap.yml has correct trigger and inputs', () => {
    it('has workflow_dispatch trigger', () => {
      expect(bootstrapYaml).toContain('workflow_dispatch:');
    });

    it('has environment input', () => {
      expect(bootstrapYaml).toContain('environment:');
      // Verify all three environment options are present
      expect(bootstrapYaml).toContain('- dev');
      expect(bootstrapYaml).toContain('- staging');
      expect(bootstrapYaml).toContain('- prod');
    });
  });

  // ── No hardcoded AWS credentials (Req 9.3) ────────────────────────

  describe('no hardcoded AWS credentials in workflow files', () => {
    it('deploy.yml does not contain AWS_ACCESS_KEY_ID', () => {
      expect(deployYaml).not.toContain('AWS_ACCESS_KEY_ID');
    });

    it('deploy.yml does not contain AWS_SECRET_ACCESS_KEY', () => {
      expect(deployYaml).not.toContain('AWS_SECRET_ACCESS_KEY');
    });

    it('bootstrap.yml does not contain AWS_ACCESS_KEY_ID', () => {
      expect(bootstrapYaml).not.toContain('AWS_ACCESS_KEY_ID');
    });

    it('bootstrap.yml does not contain AWS_SECRET_ACCESS_KEY', () => {
      expect(bootstrapYaml).not.toContain('AWS_SECRET_ACCESS_KEY');
    });
  });
});
