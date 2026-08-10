import { cpSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createBaseline } from '@dl-sentinel/core';
import { fixturePath } from '../../../tests/support/index.js';
import {
  baselineFromBase,
  diffAgainstBaseline,
  readBaselineFile,
  scanTarget,
} from '../src/scan.js';
import { defaultActionConfig, makeTmpDir } from './support.js';

const VULNERABLE = fixturePath('vulnerable-app');
const CLEAN = fixturePath('clean-app');

describe('only-new-findings diff', () => {
  let tmp: string;
  beforeAll(() => {
    tmp = makeTmpDir('scan');
  });
  afterAll(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it('with no baseline, every finding counts as new', async () => {
    const report = await scanTarget({ target: VULNERABLE, config: defaultActionConfig() });
    const result = diffAgainstBaseline(report.findings, undefined);
    expect(result.baselineApplied).toBe(false);
    expect(result.newFindings).toHaveLength(report.findings.length);
    expect(result.baselined).toBe(0);
  });

  it('baseline FILE path yields only findings absent from the file', async () => {
    const report = await scanTarget({ target: VULNERABLE, config: defaultActionConfig() });
    // Baseline a strict, non-empty subset: everything the secrets scanner found.
    const subset = report.findings.filter((f) => f.scanner === 'secrets');
    expect(subset.length).toBeGreaterThan(0);
    expect(subset.length).toBeLessThan(report.findings.length);

    const file = join(tmp, 'subset-baseline.json');
    writeFileSync(
      file,
      JSON.stringify(createBaseline(subset, { target: VULNERABLE, generatedAt: 'x' })),
    );

    const baseline = await readBaselineFile(file);
    const result = diffAgainstBaseline(report.findings, baseline);

    expect(result.baselineApplied).toBe(true);
    expect(result.baselined).toBe(subset.length);
    expect(result.newFindings).toHaveLength(report.findings.length - subset.length);
    // None of the baselined (secrets) findings survive as "new".
    expect(result.newFindings.some((f) => f.scanner === 'secrets')).toBe(false);
    const subsetIds = new Set(subset.map((f) => f.id));
    expect(result.newFindings.every((f) => !subsetIds.has(f.id))).toBe(true);
  });

  it('base-DIRECTORY path yields zero new when the base tree equals the head', async () => {
    const report = await scanTarget({ target: VULNERABLE, config: defaultActionConfig() });
    const baseline = await baselineFromBase(VULNERABLE, defaultActionConfig(), undefined);
    const result = diffAgainstBaseline(report.findings, baseline);
    expect(result.baselineApplied).toBe(true);
    expect(result.newFindings).toHaveLength(0);
    expect(result.baselined).toBe(report.findings.length);
  });

  it('base-DIRECTORY path yields only the findings the PR added', async () => {
    // head = full vulnerable app; base = same tree with .env removed. The .env
    // secret findings exist in head but not base, so they are the only "new" ones.
    const head = join(tmp, 'head');
    const base = join(tmp, 'base');
    cpSync(VULNERABLE, head, { recursive: true });
    cpSync(VULNERABLE, base, { recursive: true });
    rmSync(join(base, '.env'), { force: true });

    const report = await scanTarget({ target: head, config: defaultActionConfig() });
    const baseline = await baselineFromBase(base, defaultActionConfig(), undefined);
    const result = diffAgainstBaseline(report.findings, baseline);

    expect(result.baselineApplied).toBe(true);
    expect(result.newFindings.length).toBeGreaterThan(0);
    expect(result.newFindings.length).toBeLessThan(report.findings.length);
    // Every new finding comes from the file that only the head has.
    expect(result.newFindings.every((f) => f.file === '.env')).toBe(true);
    expect(result.baselined).toBe(report.findings.length - result.newFindings.length);
  });

  it('honors a scanner subset consistently across head and base', async () => {
    const report = await scanTarget({
      target: VULNERABLE,
      config: defaultActionConfig(),
      scanners: ['secrets'],
    });
    expect(report.findings.every((f) => f.scanner === 'secrets')).toBe(true);
    const baseline = await baselineFromBase(CLEAN, defaultActionConfig(), ['secrets']);
    const result = diffAgainstBaseline(report.findings, baseline);
    // clean-app has no secrets, so all secret findings are new.
    expect(result.newFindings).toHaveLength(report.findings.length);
  });
});

describe('readBaselineFile', () => {
  let tmp: string;
  beforeAll(() => {
    tmp = makeTmpDir('baseline');
  });
  afterAll(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it('rejects invalid JSON without echoing the file contents', async () => {
    const file = join(tmp, 'bad.json');
    const secretish = 'NOTAREALSECRET_marker_0987654321';
    writeFileSync(file, `not json ${secretish}`);
    await expect(readBaselineFile(file)).rejects.toThrow(/not valid JSON/);
    await expect(readBaselineFile(file)).rejects.not.toThrow(new RegExp(secretish));
  });

  it('rejects a JSON document of the wrong shape', async () => {
    const file = join(tmp, 'wrong.json');
    writeFileSync(file, JSON.stringify({ findings: 'nope' }));
    await expect(readBaselineFile(file)).rejects.toThrow(/not a valid DL Sentinel baseline/);
  });
});
