import { describe, expect, it } from 'vitest';
import sourceScannerDefault, { sourceScanner } from '../src/index.js';

const EXPECTED_SUPPORTED_FILES = [
  '**/*.js',
  '**/*.jsx',
  '**/*.ts',
  '**/*.tsx',
  '**/*.mjs',
  '**/*.cjs',
  '**/*.py',
  '**/*.go',
  '**/*.rb',
  '**/*.php',
  '**/*.java',
];

describe('sourceScanner plugin shape', () => {
  it('exposes the same object as default and named export', () => {
    expect(sourceScannerDefault).toBe(sourceScanner);
  });

  it('declares the contract fields required by ScannerPlugin', () => {
    expect(sourceScanner.id).toBe('source');
    expect(typeof sourceScanner.name).toBe('string');
    expect(sourceScanner.name.length).toBeGreaterThan(0);
    expect(sourceScanner.version).toMatch(/^\d+\.\d+\.\d+$/);
    expect(sourceScanner.categories).toEqual(['source']);
    expect(typeof sourceScanner.scan).toBe('function');
  });

  it('declares exactly the mission-specified supportedFiles globs', () => {
    expect(sourceScanner.supportedFiles).toEqual(EXPECTED_SUPPORTED_FILES);
  });

  it('declares ten C-namespaced rules, C001 through C010, with no gaps or duplicates', () => {
    const ids = sourceScanner.rules.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(ids.sort()).toEqual([
      'C001',
      'C002',
      'C003',
      'C004',
      'C005',
      'C006',
      'C007',
      'C008',
      'C009',
      'C010',
    ]);
  });

  it('gives every declared rule complete, non-empty metadata', () => {
    for (const rule of sourceScanner.rules) {
      expect(rule.id).toMatch(/^C\d{3}$/);
      expect(rule.title.length).toBeGreaterThan(0);
      expect(rule.description.length).toBeGreaterThan(0);
      expect(rule.recommendation.length).toBeGreaterThan(0);
      expect(['critical', 'high', 'medium', 'low', 'info']).toContain(rule.severity);
      expect(['high', 'medium', 'low']).toContain(rule.defaultConfidence);
      expect(rule.category).toBe('source');
      expect(Array.isArray(rule.references)).toBe(true);
    }
  });
});
