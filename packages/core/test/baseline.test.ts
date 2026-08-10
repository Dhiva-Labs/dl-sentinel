import { describe, expect, it } from 'vitest';
import { applyBaseline, baselineIds, createBaseline, parseBaseline } from '../src/baseline.js';
import { createFinding } from '../src/fingerprint.js';
import type { Finding } from '../src/types.js';

function finding(overrides: Partial<Omit<Finding, 'id'>> = {}): Finding {
  return createFinding({
    ruleId: 'S001',
    title: 't',
    description: 'd',
    severity: 'high',
    confidence: 'high',
    category: 'secrets',
    file: 'a.env',
    line: 1,
    evidence: 'e',
    recommendation: 'r',
    references: [],
    scanner: 'secrets',
    ...overrides,
  });
}

const META = { target: '/repo', generatedAt: '2026-08-11T00:00:00.000Z' };

describe('createBaseline', () => {
  it('records ids with context and the tool/meta', () => {
    const baseline = createBaseline([finding(), finding({ file: 'b.env', line: 2 })], META);
    expect(baseline.count).toBe(2);
    expect(baseline.generatedAt).toBe(META.generatedAt);
    expect(baseline.target).toBe('/repo');
    expect(baseline.tool.name).toBe('DL Sentinel');
    expect(baseline.findings.every((e) => e.id.length === 16)).toBe(true);
  });

  it('is deterministic and order-independent', () => {
    const a = finding({ file: 'a.env' });
    const b = finding({ file: 'b.env' });
    expect(createBaseline([a, b], META)).toEqual(createBaseline([b, a], META));
  });
});

describe('applyBaseline', () => {
  it('separates new findings from baselined ones', () => {
    const known = finding({ file: 'known.env' });
    const baseline = createBaseline([known], META);

    const brandNew = finding({ file: 'new.env' });
    const result = applyBaseline([known, brandNew], baseline);

    expect(result.baselined).toEqual([known]);
    expect(result.newFindings).toEqual([brandNew]);
  });

  it('treats an empty baseline as everything-new', () => {
    const baseline = createBaseline([], META);
    const result = applyBaseline([finding()], baseline);
    expect(result.newFindings).toHaveLength(1);
    expect(result.baselined).toHaveLength(0);
  });

  it('baselineIds exposes the id set', () => {
    const f = finding();
    expect(baselineIds(createBaseline([f], META)).has(f.id)).toBe(true);
  });
});

describe('parseBaseline (untrusted input)', () => {
  it('round-trips a created baseline through JSON', () => {
    const baseline = createBaseline([finding()], META);
    const parsed = parseBaseline(JSON.parse(JSON.stringify(baseline)));
    expect(parsed.findings.map((f) => f.id)).toEqual(baseline.findings.map((f) => f.id));
  });

  it('rejects non-objects and malformed shapes', () => {
    expect(() => parseBaseline(null)).toThrow(/object/);
    expect(() => parseBaseline('nope')).toThrow(/object/);
    expect(() => parseBaseline({})).toThrow(/findings must be an array/);
    expect(() => parseBaseline({ findings: [{}] })).toThrow(/id must be a non-empty string/);
  });

  it('tolerates missing optional context fields', () => {
    const parsed = parseBaseline({ findings: [{ id: 'abc123' }] });
    expect(parsed.findings[0]?.id).toBe('abc123');
    expect(parsed.findings[0]?.severity).toBe('info');
  });
});
