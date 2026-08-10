import { describe, expect, it } from 'vitest';
import { createFinding } from '../src/fingerprint.js';
import {
  applySuppressions,
  isActionableRule,
  isExpired,
  isSuppressed,
  ruleMatches,
} from '../src/suppressions.js';
import type { Finding, SuppressionRule } from '../src/types.js';

function finding(overrides: Partial<Omit<Finding, 'id'>> = {}): Finding {
  return createFinding({
    ruleId: 'S001',
    title: 't',
    description: 'd',
    severity: 'critical',
    confidence: 'high',
    category: 'secrets',
    file: 'config/app.env',
    line: 1,
    evidence: 'API_KEY=[REDACTED]',
    recommendation: 'r',
    references: [],
    scanner: 'secrets',
    ...overrides,
  });
}

const NOW = new Date('2026-08-11T00:00:00.000Z');

describe('isActionableRule', () => {
  it('is false for an empty rule (never suppresses everything)', () => {
    expect(isActionableRule({})).toBe(false);
    expect(isActionableRule({ reason: 'just because' })).toBe(false);
  });

  it('is true when any matcher is present', () => {
    expect(isActionableRule({ rule: 'S001' })).toBe(true);
    expect(isActionableRule({ path: '**/*.env' })).toBe(true);
    expect(isActionableRule({ scanner: 'secrets' })).toBe(true);
    expect(isActionableRule({ id: 'abc' })).toBe(true);
  });
});

describe('isExpired', () => {
  it('is false without an expiry', () => {
    expect(isExpired({ rule: 'S001' }, NOW)).toBe(false);
  });

  it('is true on or after the expiry instant', () => {
    expect(isExpired({ rule: 'S001', expires: '2026-08-10T00:00:00Z' }, NOW)).toBe(true);
    expect(isExpired({ rule: 'S001', expires: '2026-08-11T00:00:00Z' }, NOW)).toBe(true);
  });

  it('is false before the expiry', () => {
    expect(isExpired({ rule: 'S001', expires: '2026-08-12T00:00:00Z' }, NOW)).toBe(false);
  });

  it('treats an unparseable expiry as non-expiring', () => {
    expect(isExpired({ rule: 'S001', expires: 'not-a-date' }, NOW)).toBe(false);
  });
});

describe('ruleMatches (AND across a rule fields)', () => {
  it('matches by rule id', () => {
    expect(ruleMatches({ rule: 'S001' }, finding(), NOW)).toBe(true);
    expect(ruleMatches({ rule: 'S002' }, finding(), NOW)).toBe(false);
  });

  it('matches by scanner', () => {
    expect(ruleMatches({ scanner: 'secrets' }, finding(), NOW)).toBe(true);
    expect(ruleMatches({ scanner: 'source' }, finding(), NOW)).toBe(false);
  });

  it('matches by path glob', () => {
    expect(ruleMatches({ path: '**/*.env' }, finding(), NOW)).toBe(true);
    expect(ruleMatches({ path: 'src/**' }, finding(), NOW)).toBe(false);
  });

  it('matches by exact id', () => {
    const f = finding();
    expect(ruleMatches({ id: f.id }, f, NOW)).toBe(true);
    expect(ruleMatches({ id: 'nope' }, f, NOW)).toBe(false);
  });

  it('requires all specified fields to match', () => {
    expect(ruleMatches({ rule: 'S001', path: '**/*.env' }, finding(), NOW)).toBe(true);
    expect(ruleMatches({ rule: 'S001', path: 'src/**' }, finding(), NOW)).toBe(false);
  });

  it('an empty or expired rule never matches', () => {
    expect(ruleMatches({}, finding(), NOW)).toBe(false);
    expect(ruleMatches({ rule: 'S001', expires: '2020-01-01T00:00:00Z' }, finding(), NOW)).toBe(
      false,
    );
  });
});

describe('applySuppressions', () => {
  it('returns everything active when there are no rules', () => {
    const findings = [finding(), finding({ ruleId: 'S002' })];
    const result = applySuppressions(findings, [], NOW);
    expect(result.active).toHaveLength(2);
    expect(result.suppressed).toHaveLength(0);
  });

  it('partitions matched findings into suppressed', () => {
    const keep = finding({ ruleId: 'C001', file: 'src/a.ts', scanner: 'source' });
    const drop = finding();
    const rules: SuppressionRule[] = [{ rule: 'S001', path: '**/*.env', reason: 'known test env' }];
    const result = applySuppressions([keep, drop], rules, NOW);
    expect(result.active).toEqual([keep]);
    expect(result.suppressed).toEqual([drop]);
  });

  it('an expired rule suppresses nothing (finding resurfaces)', () => {
    const rules: SuppressionRule[] = [{ rule: 'S001', expires: '2000-01-01T00:00:00Z' }];
    const result = applySuppressions([finding()], rules, NOW);
    expect(result.active).toHaveLength(1);
    expect(result.suppressed).toHaveLength(0);
  });

  it('isSuppressed matches any rule (OR across rules)', () => {
    const rules: SuppressionRule[] = [{ rule: 'S999' }, { scanner: 'secrets' }];
    expect(isSuppressed(finding(), rules, NOW)).toBe(true);
  });
});
