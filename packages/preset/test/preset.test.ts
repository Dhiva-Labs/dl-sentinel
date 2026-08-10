import { describe, expect, it } from 'vitest';
import { BUILTIN_SCANNERS, createDefaultEngine } from '../src/index.js';

describe('BUILTIN_SCANNERS', () => {
  it('contains exactly the six built-in scanners in stable order', () => {
    expect(BUILTIN_SCANNERS.map((s) => s.id)).toEqual([
      'secrets',
      'dependencies',
      'source',
      'infra',
      'api',
      'smart-contract',
    ]);
  });

  it('exposes unique scanner ids', () => {
    const ids = BUILTIN_SCANNERS.map((s) => s.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('every scanner declares at least one rule with a namespaced id', () => {
    for (const scanner of BUILTIN_SCANNERS) {
      expect(scanner.rules.length).toBeGreaterThan(0);
      for (const rule of scanner.rules) {
        expect(rule.id).toMatch(/^(S|D|C|I|A|SC)\d+$/);
      }
    }
  });

  it('is frozen', () => {
    expect(Object.isFrozen(BUILTIN_SCANNERS)).toBe(true);
  });
});

describe('createDefaultEngine', () => {
  it('registers every built-in scanner in order', () => {
    const engine = createDefaultEngine();
    expect(engine.plugins().map((p) => p.id)).toEqual(BUILTIN_SCANNERS.map((s) => s.id));
  });

  it('returns an independent engine each call', () => {
    expect(createDefaultEngine()).not.toBe(createDefaultEngine());
  });

  it('produces an engine that scans without error', async () => {
    const engine = createDefaultEngine();
    const report = await engine.scan({ target: process.cwd() });
    expect(report.errors).toEqual([]);
    expect(report.scannersRun).toEqual([
      'secrets',
      'dependencies',
      'source',
      'infra',
      'api',
      'smart-contract',
    ]);
  });
});
