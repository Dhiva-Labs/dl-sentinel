import { describe, expect, it } from 'vitest';
import { SEVERITIES, severityClass, severityLabel, severityRank } from '../src/severity.js';
import type { Severity } from '../src/types.js';

describe('SEVERITIES', () => {
  it('lists all five severities, most severe first', () => {
    expect(SEVERITIES).toEqual(['critical', 'high', 'medium', 'low', 'info']);
  });
});

describe('severityClass', () => {
  it('prefixes the severity with "sev-"', () => {
    expect(severityClass('critical')).toBe('sev-critical');
    expect(severityClass('high')).toBe('sev-high');
    expect(severityClass('medium')).toBe('sev-medium');
    expect(severityClass('low')).toBe('sev-low');
    expect(severityClass('info')).toBe('sev-info');
  });
});

describe('severityLabel', () => {
  it('capitalizes the first letter only', () => {
    expect(severityLabel('critical')).toBe('Critical');
    expect(severityLabel('info')).toBe('Info');
  });
});

describe('severityRank', () => {
  it('orders critical before info', () => {
    expect(severityRank('critical')).toBeLessThan(severityRank('high'));
    expect(severityRank('high')).toBeLessThan(severityRank('medium'));
    expect(severityRank('medium')).toBeLessThan(severityRank('low'));
    expect(severityRank('low')).toBeLessThan(severityRank('info'));
  });

  it('sorts unknown values last', () => {
    expect(severityRank('bogus' as Severity)).toBe(SEVERITIES.length);
  });
});
