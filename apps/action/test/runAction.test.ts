import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createBaseline } from '@dl-sentinel/core';
import { PLANTED_SECRET_VALUES, fixturePath } from '../../../tests/support/index.js';
import { runAction } from '../src/action.js';
import { EXIT } from '../src/exit-codes.js';
import { scanTarget } from '../src/scan.js';
import { captureIO, fakeFetch, throwingFetch } from './helpers.js';
import { defaultActionConfig, makeEnv, makeTmpDir, writePrEvent } from './support.js';

const VULNERABLE = fixturePath('vulnerable-app');
const CLEAN = fixturePath('clean-app');

/** Parse a $GITHUB_OUTPUT file (name=value lines) into a map. */
function readOutputs(file: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of readFileSync(file, 'utf8').split('\n')) {
    const eq = line.indexOf('=');
    if (eq > 0) out[line.slice(0, eq)] = line.slice(eq + 1);
  }
  return out;
}

describe('runAction', () => {
  let tmp: string;
  beforeAll(() => {
    tmp = makeTmpDir('run');
  });
  afterAll(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it('fails (exit 1) on a new critical finding and writes SARIF, summary, and outputs', async () => {
    const { env, sarifFile, summaryFile, outputFile } = makeEnv(tmp, VULNERABLE);
    const { io } = captureIO(env, throwingFetch());

    const code = await runAction(io);
    expect(code).toBe(EXIT.POLICY);

    // Outputs.
    const outputs = readOutputs(outputFile);
    expect(Number(outputs.findings_total)).toBeGreaterThan(0);
    expect(outputs.findings_new).toBe(outputs.findings_total); // no baseline ⇒ all new
    expect(outputs.failed).toBe('true');

    // SARIF present, well-formed, and carries the new findings.
    expect(existsSync(sarifFile)).toBe(true);
    const sarif = JSON.parse(readFileSync(sarifFile, 'utf8')) as {
      version: string;
      runs: { results: unknown[] }[];
    };
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0]?.results.length).toBe(Number(outputs.findings_new));

    // Step summary carries the marker and the counts.
    const summary = readFileSync(summaryFile, 'utf8');
    expect(summary).toContain('<!-- dl-sentinel -->');
    expect(summary).toContain('| Critical |');

    // No planted secret anywhere the action produced.
    for (const secret of PLANTED_SECRET_VALUES) {
      expect(summary, `secret in summary: ${secret}`).not.toContain(secret);
      expect(readFileSync(sarifFile, 'utf8'), `secret in sarif: ${secret}`).not.toContain(secret);
    }
  });

  it('passes (exit 0) on a clean tree', async () => {
    const { env, outputFile } = makeEnv(tmp, CLEAN);
    const { io } = captureIO(env, throwingFetch());
    const code = await runAction(io);
    expect(code).toBe(EXIT.OK);
    const outputs = readOutputs(outputFile);
    expect(outputs.failed).toBe('false');
  });

  it('passes (exit 0) when every finding is baselined by a committed baseline file', async () => {
    const report = await scanTarget({ target: VULNERABLE, config: defaultActionConfig() });
    const baselineFile = join(tmp, 'full-baseline.json');
    writeFileSync(
      baselineFile,
      JSON.stringify(createBaseline(report.findings, { target: VULNERABLE, generatedAt: 'x' })),
    );

    const { env, outputFile, sarifFile } = makeEnv(tmp, VULNERABLE, {
      INPUT_BASELINE: baselineFile,
    });
    const { io } = captureIO(env, throwingFetch());

    const code = await runAction(io);
    expect(code).toBe(EXIT.OK);
    const outputs = readOutputs(outputFile);
    expect(outputs.findings_new).toBe('0');
    expect(Number(outputs.findings_total)).toBeGreaterThan(0);
    expect(outputs.failed).toBe('false');
    // SARIF reflects only the (zero) new findings.
    const sarif = JSON.parse(readFileSync(sarifFile, 'utf8')) as { runs: { results: unknown[] }[] };
    expect(sarif.runs[0]?.results).toHaveLength(0);
  });

  it('passes (exit 0) when the base tree scan baselines everything', async () => {
    // base_path equal to the workspace ⇒ base == head ⇒ nothing new.
    const { env, outputFile } = makeEnv(tmp, VULNERABLE, { INPUT_BASE_PATH: VULNERABLE });
    const { io } = captureIO(env, throwingFetch());
    const code = await runAction(io);
    expect(code).toBe(EXIT.OK);
    expect(readOutputs(outputFile).findings_new).toBe('0');
  });

  it('creates a sticky PR comment via the injected fetch on a pull_request event', async () => {
    const eventPath = writePrEvent(join(tmp, 'pr-create.json'));
    const { env } = makeEnv(tmp, VULNERABLE, {
      GITHUB_EVENT_NAME: 'pull_request',
      GITHUB_EVENT_PATH: eventPath,
      GITHUB_REPOSITORY: 'octo/repo',
      INPUT_TOKEN: 'ghs_FAKE',
    });
    const fake = fakeFetch({ listComments: [] });
    const { io } = captureIO(env, fake.fetch);

    const code = await runAction(io);
    expect(code).toBe(EXIT.POLICY); // vulnerable ⇒ still fails, but comment is posted

    expect(fake.requests[0]?.method).toBe('GET');
    const create = fake.requests[1];
    expect(create?.method).toBe('POST');
    expect(create?.url).toBe('https://api.github.com/repos/octo/repo/issues/7/comments');
    expect(create?.headers.Authorization).toBe('Bearer ghs_FAKE');
    const posted = JSON.parse(create?.body ?? '{}') as { body: string };
    expect(posted.body).toContain('<!-- dl-sentinel -->');
    for (const secret of PLANTED_SECRET_VALUES) {
      expect(posted.body, `secret in comment: ${secret}`).not.toContain(secret);
    }
  });

  it('updates the existing sticky comment via PATCH', async () => {
    const eventPath = writePrEvent(join(tmp, 'pr-update.json'));
    const { env } = makeEnv(tmp, CLEAN, {
      GITHUB_EVENT_NAME: 'pull_request',
      GITHUB_EVENT_PATH: eventPath,
      GITHUB_REPOSITORY: 'octo/repo',
      INPUT_TOKEN: 'ghs_FAKE',
    });
    const fake = fakeFetch({ listComments: [{ id: 88, body: 'old <!-- dl-sentinel --> body' }] });
    const { io } = captureIO(env, fake.fetch);

    const code = await runAction(io);
    expect(code).toBe(EXIT.OK);
    const patch = fake.requests[1];
    expect(patch?.method).toBe('PATCH');
    expect(patch?.url).toBe('https://api.github.com/repos/octo/repo/issues/comments/88');
  });

  it('skips commenting (without throwing) when no token is present', async () => {
    const eventPath = writePrEvent(join(tmp, 'pr-notoken.json'));
    const { env } = makeEnv(tmp, CLEAN, {
      GITHUB_EVENT_NAME: 'pull_request',
      GITHUB_EVENT_PATH: eventPath,
      GITHUB_REPOSITORY: 'octo/repo',
      // no INPUT_TOKEN / GITHUB_TOKEN
    });
    const { io, out } = captureIO(env, throwingFetch());

    const code = await runAction(io);
    expect(code).toBe(EXIT.OK);
    expect(out()).toContain('No token available');
  });

  it('does not comment when comment is disabled, even on a PR event with a token', async () => {
    const eventPath = writePrEvent(join(tmp, 'pr-nocomment.json'));
    const { env } = makeEnv(tmp, CLEAN, {
      GITHUB_EVENT_NAME: 'pull_request',
      GITHUB_EVENT_PATH: eventPath,
      GITHUB_REPOSITORY: 'octo/repo',
      INPUT_TOKEN: 'ghs_FAKE',
      INPUT_COMMENT: 'false',
    });
    const fake = fakeFetch({ listComments: [] });
    const { io } = captureIO(env, fake.fetch);

    await runAction(io);
    expect(fake.requests).toHaveLength(0);
  });

  it('does not write SARIF when sarif is disabled', async () => {
    const { env, sarifFile } = makeEnv(tmp, CLEAN, { INPUT_SARIF: 'false' });
    const { io } = captureIO(env, throwingFetch());
    await runAction(io);
    expect(existsSync(sarifFile)).toBe(false);
  });

  it('returns EXIT.ERROR on an invalid fail_on without throwing', async () => {
    const { env } = makeEnv(tmp, CLEAN, { INPUT_FAIL_ON: 'critical,bogus' });
    const { io, out } = captureIO(env, throwingFetch());
    const code = await runAction(io);
    expect(code).toBe(EXIT.ERROR);
    expect(out()).toContain('::error::');
  });
});
