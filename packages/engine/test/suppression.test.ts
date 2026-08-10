import { describe, expect, it } from 'vitest';
import type { SentinelConfig } from '@dl-sentinel/core';
import { defaultConfig } from '@dl-sentinel/core';
import { createEngine } from '../src/index.js';
import { FIXTURE_TREE, findingInput, mockPlugin, pluginReturning, testFinding } from './helpers.js';

function withSuppress(suppress: NonNullable<SentinelConfig['suppress']>): SentinelConfig {
  return { ...defaultConfig(), suppress };
}

describe('scan: suppression', () => {
  it('suppresses findings matching a rule id and computes stats from the survivors', async () => {
    const engine = createEngine();
    engine.register(
      pluginReturning('secrets', [
        findingInput({ ruleId: 'S001', file: 'a.env', severity: 'critical' }),
        findingInput({ ruleId: 'S002', file: 'b.env', severity: 'high' }),
      ]),
    );

    const report = await engine.scan({
      target: FIXTURE_TREE,
      config: withSuppress([{ rule: 'S001' }]),
    });

    expect(report.findings.map((f) => f.ruleId)).toEqual(['S002']);
    expect(report.suppressed).toBe(1);
    expect(report.stats).toEqual({ critical: 0, high: 1, medium: 0, low: 0, info: 0 });
  });

  it('suppresses findings by file glob path', async () => {
    const engine = createEngine();
    engine.register(
      pluginReturning('source', [
        findingInput({ file: 'src/app.ts' }),
        findingInput({ file: 'src/app.test.ts' }),
      ]),
    );

    const report = await engine.scan({
      target: FIXTURE_TREE,
      config: withSuppress([{ path: '**/*.test.ts' }]),
    });

    expect(report.findings.map((f) => f.file)).toEqual(['src/app.ts']);
    expect(report.suppressed).toBe(1);
  });

  it('suppresses findings by scanner id', async () => {
    const engine = createEngine();
    engine.register(pluginReturning('alpha', [findingInput({ file: 'a.ts' })]));
    engine.register(pluginReturning('beta', [findingInput({ file: 'b.ts' })]));

    const report = await engine.scan({
      target: FIXTURE_TREE,
      config: withSuppress([{ scanner: 'beta' }]),
    });

    expect(report.findings.map((f) => f.scanner)).toEqual(['alpha']);
    expect(report.suppressed).toBe(1);
  });

  it('suppresses a single finding pinned by its fingerprint id', async () => {
    const pinned = testFinding({ scanner: 'alpha', file: 'src/app.ts' });
    const other = testFinding({ scanner: 'alpha', file: 'src/util.ts' });
    const engine = createEngine();
    engine.register(mockPlugin({ id: 'alpha', scan: async () => [pinned, other] }));

    const report = await engine.scan({
      target: FIXTURE_TREE,
      config: withSuppress([{ id: pinned.id }]),
    });

    expect(report.findings.map((f) => f.id)).toEqual([other.id]);
    expect(report.suppressed).toBe(1);
  });

  it('requires every specified field of a rule to match (AND)', async () => {
    const engine = createEngine();
    engine.register(
      pluginReturning('secrets', [
        findingInput({ ruleId: 'S001', file: 'src/a.env' }),
        findingInput({ ruleId: 'S001', file: 'test/a.env' }),
      ]),
    );

    // rule id AND path: only the finding under test/ matches both.
    const report = await engine.scan({
      target: FIXTURE_TREE,
      config: withSuppress([{ rule: 'S001', path: 'test/**' }]),
    });

    expect(report.findings.map((f) => f.file)).toEqual(['src/a.env']);
    expect(report.suppressed).toBe(1);
  });

  it('resurfaces a finding once its suppression rule has expired', async () => {
    const engine = createEngine();
    engine.register(pluginReturning('secrets', [findingInput({ ruleId: 'S001', file: 'a.env' })]));

    const report = await engine.scan({
      target: FIXTURE_TREE,
      config: withSuppress([{ rule: 'S001', expires: '2000-01-01' }]),
    });

    // The rule is configured (so `suppressed` is defined) but lapsed, so the
    // finding is reported again and nothing was suppressed.
    expect(report.findings.map((f) => f.ruleId)).toEqual(['S001']);
    expect(report.suppressed).toBe(0);
  });

  it('keeps suppressing while the expiry is still in the future', async () => {
    const engine = createEngine();
    engine.register(pluginReturning('secrets', [findingInput({ ruleId: 'S001', file: 'a.env' })]));

    const report = await engine.scan({
      target: FIXTURE_TREE,
      config: withSuppress([{ rule: 'S001', expires: '2999-01-01' }]),
    });

    expect(report.findings).toEqual([]);
    expect(report.suppressed).toBe(1);
  });

  it('leaves report.suppressed undefined when no suppression is configured', async () => {
    const engine = createEngine();
    engine.register(pluginReturning('alpha', [findingInput()]));

    const withDefaults = await engine.scan({ target: FIXTURE_TREE });
    expect(withDefaults.suppressed).toBeUndefined();

    const withEmpty = await engine.scan({ target: FIXTURE_TREE, config: withSuppress([]) });
    expect(withEmpty.suppressed).toBeUndefined();
  });

  it('ignores a rule that specifies no matcher', async () => {
    const engine = createEngine();
    engine.register(pluginReturning('alpha', [findingInput({ file: 'a.ts' })]));

    const report = await engine.scan({
      target: FIXTURE_TREE,
      config: withSuppress([{ reason: 'no matcher, so it hides nothing' }]),
    });

    expect(report.findings).toHaveLength(1);
    expect(report.suppressed).toBe(0);
  });
});
