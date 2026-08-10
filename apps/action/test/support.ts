import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { SentinelConfig } from '@dl-sentinel/core';
import { defaultConfig } from '@dl-sentinel/core';

/** A plain default config for direct scanTarget() calls in unit tests. */
export function defaultActionConfig(): SentinelConfig {
  return defaultConfig();
}

/** Create a throwaway temp directory (removed by the test's afterAll). */
export function makeTmpDir(tag: string): string {
  return mkdtempSync(join(tmpdir(), `dl-sentinel-action-${tag}-`));
}

export interface ActionEnv {
  env: NodeJS.ProcessEnv;
  /** Path the SARIF file is written to. */
  sarifFile: string;
  /** Path $GITHUB_STEP_SUMMARY points at. */
  summaryFile: string;
  /** Path $GITHUB_OUTPUT points at. */
  outputFile: string;
}

let counter = 0;

/**
 * Build an environment for `runAction`, with the three GitHub env files pointed
 * at unique paths under `tmp` so a test can read them back. `overrides` are
 * merged last, so a test can add INPUT_* / GITHUB_* vars or replace a default.
 */
export function makeEnv(
  tmp: string,
  workspace: string,
  overrides: NodeJS.ProcessEnv = {},
): ActionEnv {
  const tag = `${counter++}`;
  const sarifFile = join(tmp, `${tag}.sarif`);
  const summaryFile = join(tmp, `${tag}.summary.md`);
  const outputFile = join(tmp, `${tag}.output.txt`);
  const env: NodeJS.ProcessEnv = {
    GITHUB_WORKSPACE: workspace,
    INPUT_PATH: '.',
    INPUT_SARIF_FILE: sarifFile,
    GITHUB_STEP_SUMMARY: summaryFile,
    GITHUB_OUTPUT: outputFile,
    GITHUB_EVENT_NAME: 'push',
    ...overrides,
  };
  return { env, sarifFile, summaryFile, outputFile };
}

/**
 * Write a fake `pull_request` event payload to `path` and return it, so a test
 * can point GITHUB_EVENT_PATH at a realistic webhook body.
 */
export function writePrEvent(
  path: string,
  opts: { number: number; repoFullName: string } = { number: 7, repoFullName: 'octo/repo' },
): string {
  const payload = {
    number: opts.number,
    repository: { full_name: opts.repoFullName },
    pull_request: {
      number: opts.number,
      base: { sha: 'basesha', ref: 'main' },
      head: { sha: 'headsha' },
    },
  };
  writeFileSync(path, JSON.stringify(payload), 'utf8');
  return path;
}
