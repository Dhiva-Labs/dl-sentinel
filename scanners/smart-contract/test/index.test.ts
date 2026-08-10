import { readFileSync } from 'node:fs';
import type { FileRef, ScanLogger } from '@dl-sentinel/core';
import { describe, expect, it } from 'vitest';
import namedExport, { smartContractScanner } from '../src/index.js';
import { contextFor, fileRefFor } from './helpers.js';

describe('smartContractScanner: plugin shape', () => {
  it('exposes the required ScannerPlugin fields', () => {
    expect(smartContractScanner.id).toBe('smart-contract');
    expect(smartContractScanner.name).toBeTruthy();
    expect(smartContractScanner.version).toBeTruthy();
    expect(smartContractScanner.categories).toEqual(['smart-contract']);
    expect(smartContractScanner.supportedFiles).toEqual(['**/*.sol']);
    expect(typeof smartContractScanner.scan).toBe('function');
  });

  it('the default export is the same object as the named export', () => {
    expect(namedExport).toBe(smartContractScanner);
  });

  it('declares all twelve rules with complete RuleMeta', () => {
    const ids = smartContractScanner.rules.map((r) => r.id).sort();
    expect(ids).toEqual([
      'SC001',
      'SC002',
      'SC003',
      'SC004',
      'SC005',
      'SC006',
      'SC007',
      'SC008',
      'SC009',
      'SC010',
      'SC011',
      'SC012',
    ]);
    for (const rule of smartContractScanner.rules) {
      expect(rule.id).toMatch(/^SC\d{3}$/);
      expect(rule.title).toBeTruthy();
      expect(rule.description).toBeTruthy();
      expect(rule.recommendation).toBeTruthy();
      expect(['critical', 'high', 'medium', 'low', 'info']).toContain(rule.severity);
      expect(['high', 'medium', 'low']).toContain(rule.defaultConfidence);
      expect(rule.category).toBe('smart-contract');
    }
  });

  it('rule ids have no duplicates', () => {
    const ids = smartContractScanner.rules.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});

describe('smartContractScanner: scan()', () => {
  it('returns findings that are all well-formed Findings', async () => {
    const context = contextFor([fileRefFor('sc001-positive.sol')]);
    const findings = await smartContractScanner.scan(context);
    expect(findings.length).toBeGreaterThan(0);
    for (const f of findings) {
      expect(f.id).toMatch(/^[0-9a-f]{16}$/);
      expect(f.scanner).toBe('smart-contract');
      expect(f.category).toBe('smart-contract');
      expect(f.file).toBe('sc001-positive.sol');
      expect(Array.isArray(f.references)).toBe(true);
      expect(typeof f.evidence).toBe('string');
      expect(f.evidence.length).toBeGreaterThan(0);
    }
  });

  it('never includes an unredacted secret-looking marker beyond source text (evidence is just trimmed source)', async () => {
    const context = contextFor([fileRefFor('sc001-positive.sol')]);
    const findings = await smartContractScanner.scan(context);
    for (const f of findings) {
      expect(f.evidence).toBe(f.evidence.trim());
    }
  });

  it('is deterministic: two scans of the same multi-file input produce identical results', async () => {
    const files = [
      fileRefFor('sc001-positive.sol'),
      fileRefFor('sc002-positive.sol'),
      fileRefFor('sc005-positive.sol'),
      fileRefFor('sc011-positive.sol'),
    ];
    const [first, second] = await Promise.all([
      smartContractScanner.scan(contextFor(files)),
      smartContractScanner.scan(contextFor(files)),
    ]);
    expect(first).toEqual(second);
  });

  it('sorts output (does not depend on input file order for its own internal consistency)', async () => {
    const files = [fileRefFor('sc001-positive.sol'), fileRefFor('sc002-positive.sol')];
    const forward = await smartContractScanner.scan(contextFor(files));
    const reversed = await smartContractScanner.scan(contextFor([...files].reverse()));
    expect(forward).toEqual(reversed);
  });

  it('honors an already-aborted signal by throwing rather than returning findings', async () => {
    const controller = new AbortController();
    controller.abort();
    const context = contextFor([fileRefFor('sc001-positive.sol')], { signal: controller.signal });
    await expect(smartContractScanner.scan(context)).rejects.toThrow();
  });

  it('returns no findings for an empty file list', async () => {
    const findings = await smartContractScanner.scan(contextFor([]));
    expect(findings).toEqual([]);
  });

  it('warns and skips a malformed file without crashing, and still scans the rest', async () => {
    const warnings: string[] = [];
    const logger: ScanLogger = {
      debug: () => {},
      info: () => {},
      warn: (msg) => warnings.push(msg),
      error: () => {},
    };
    const malformed: FileRef = fileRefFor('parser/malformed-unbalanced-braces.sol');
    const files = [malformed, fileRefFor('sc001-positive.sol')];
    const context = contextFor(files, { logger });

    const findings = await smartContractScanner.scan(context);

    expect(warnings.length).toBeGreaterThan(0);
    // The well-formed file's findings are still present.
    expect(findings.some((f) => f.file === 'sc001-positive.sol' && f.ruleId === 'SC001')).toBe(
      true,
    );
  });

  it('does not crash on a truncated file (unclosed braces at EOF)', async () => {
    const context = contextFor([fileRefFor('parser/malformed-truncated.sol')]);
    await expect(smartContractScanner.scan(context)).resolves.toBeDefined();
  });

  it('does not crash on a file that reads as completely empty', async () => {
    const ref = fileRefFor('sc001-positive.sol'); // path is irrelevant; content is stubbed below
    const context = contextFor([ref], { readFile: () => Promise.resolve('') });
    const findings = await smartContractScanner.scan(context);
    expect(findings).toEqual([]);
  });

  it('a readFile failure for one file is logged and does not abort the whole scan', async () => {
    const warnings: string[] = [];
    const logger: ScanLogger = {
      debug: () => {},
      info: () => {},
      warn: (msg) => warnings.push(msg),
      error: () => {},
    };
    const goodRef = fileRefFor('sc001-positive.sol');
    const badRef: FileRef = {
      absPath: '/nonexistent/does-not-exist.sol',
      relPath: 'ghost.sol',
      size: 0,
    };
    const context = contextFor([badRef, goodRef], {
      logger,
      readFile: (ref) =>
        ref === badRef
          ? Promise.reject(new Error('ENOENT'))
          : Promise.resolve(readFileSync(ref.absPath, 'utf8')),
    });

    const findings = await smartContractScanner.scan(context);
    expect(warnings.some((w) => w.includes('ghost.sol'))).toBe(true);
    expect(findings.some((f) => f.file === 'sc001-positive.sol')).toBe(true);
  });
});
