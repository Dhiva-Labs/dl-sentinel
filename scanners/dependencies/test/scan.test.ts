import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
import type { ScanContext } from '@dl-sentinel/core';
import { noopLogger, sortFindings } from '@dl-sentinel/core';
import {
  fixturePath as sharedFixturePath,
  listFixtureFiles,
  makeScanContext,
} from '../../../tests/support/index.js';
import dependenciesScanner, { dependenciesScanner as namedScanner } from '../src/index.js';
import { contextFor, fileRef, fixturePath } from './support.js';

const ADVISORY_DB = fixturePath('advisory-db', 'valid.json');

describe('dependenciesScanner plugin shape', () => {
  it('exports the same object as default and named export', () => {
    expect(dependenciesScanner).toBe(namedScanner);
  });

  it('declares the documented contract fields', () => {
    expect(dependenciesScanner.id).toBe('dependencies');
    expect(dependenciesScanner.categories).toEqual(['dependencies']);
    expect(dependenciesScanner.supportedFiles).toEqual([
      '**/package.json',
      '**/package-lock.json',
      '**/yarn.lock',
      '**/pnpm-lock.yaml',
      '**/requirements.txt',
      '**/requirements-*.txt',
      '**/go.mod',
      '**/Cargo.toml',
      '**/Cargo.lock',
    ]);
    expect(dependenciesScanner.rules.map((r) => r.id)).toEqual(['D001', 'D002', 'D003']);
    for (const rule of dependenciesScanner.rules) {
      expect(rule.id).toMatch(/^D\d{3}$/);
      expect(rule.category).toBe('dependencies');
      expect(rule.description.length).toBeGreaterThan(0);
      expect(rule.recommendation.length).toBeGreaterThan(0);
    }
  });
});

describe('scan() against tests/fixtures/vulnerable-app via FileDataSource (read-only shared fixture)', () => {
  it('flags lodash 4.17.15 and minimist 1.2.0 using real, faithfully-copied GHSA advisories', async () => {
    const vulnerableApp = sharedFixturePath('vulnerable-app');
    const allFiles = listFixtureFiles(vulnerableApp);
    const depFiles = allFiles.filter(
      (f) => f.relPath === 'package.json' || f.relPath === 'package-lock.json',
    );
    expect(depFiles.length).toBe(2);

    const context = makeScanContext(vulnerableApp, depFiles, {
      dataSource: 'file',
      advisoryDbPath: ADVISORY_DB,
    });
    const findings = await dependenciesScanner.scan(context);
    const d001 = findings.filter((f) => f.ruleId === 'D001');

    const lodashFindings = d001.filter((f) => f.evidence.startsWith('lodash@4.17.15'));
    const minimistFindings = d001.filter((f) => f.evidence.startsWith('minimist@1.2.0'));

    // lodash 4.17.15 matches two distinct real advisories, from both the
    // exact lockfile version (high confidence) and the declared manifest
    // range (medium confidence).
    expect(lodashFindings.length).toBe(4);
    expect(
      lodashFindings.some((f) => f.file === 'package-lock.json' && f.confidence === 'high'),
    ).toBe(true);
    expect(lodashFindings.some((f) => f.file === 'package.json' && f.confidence === 'medium')).toBe(
      true,
    );

    // minimist 1.2.0 matches its one real advisory, again from both files.
    expect(minimistFindings.length).toBe(2);
    expect(
      minimistFindings.some((f) => f.file === 'package-lock.json' && f.confidence === 'high'),
    ).toBe(true);
    expect(
      minimistFindings.some((f) => f.file === 'package.json' && f.confidence === 'medium'),
    ).toBe(true);

    const ids = new Set(d001.map((f) => f.evidence.match(/\(([^)]+)\)/)?.[1]));
    expect(ids).toEqual(
      new Set(['GHSA-35jh-r3h4-6jhm', 'GHSA-p6mc-m468-83gw', 'GHSA-xvch-5gv4-984h']),
    );

    // Every finding stays a whole-severity vulnerability finding: never info.
    for (const finding of d001) {
      expect(['critical', 'high', 'medium', 'low']).toContain(finding.severity);
      expect(finding.scanner).toBe('dependencies');
    }
  });

  it('reports "not checked" (D002) instead of any vulnerability claim when dataSource is none', async () => {
    const vulnerableApp = sharedFixturePath('vulnerable-app');
    const depFiles = listFixtureFiles(vulnerableApp).filter(
      (f) => f.relPath === 'package.json' || f.relPath === 'package-lock.json',
    );
    const context = makeScanContext(vulnerableApp, depFiles, {});
    const findings = await dependenciesScanner.scan(context);

    expect(findings.every((f) => f.ruleId === 'D002')).toBe(true);
    expect(findings.length).toBe(2);
  });
});

describe('determinism', () => {
  function multiEcosystemFiles() {
    return [
      fileRef(fixturePath('npm', 'well-formed', 'package.json'), 'npm/package.json'),
      fileRef(fixturePath('npm', 'well-formed', 'package-lock.json'), 'npm/package-lock.json'),
      fileRef(fixturePath('pip', 'well-formed', 'requirements.txt'), 'pip/requirements.txt'),
      fileRef(fixturePath('go', 'well-formed', 'go.mod'), 'go/go.mod'),
      fileRef(fixturePath('cargo', 'well-formed', 'Cargo.toml'), 'cargo/Cargo.toml'),
      fileRef(fixturePath('cargo', 'well-formed', 'Cargo.lock'), 'cargo/Cargo.lock'),
    ];
  }

  it('produces byte-identical, already-sorted output across two independent runs (dataSource: none)', async () => {
    const first = await dependenciesScanner.scan(
      contextFor('/fake-root', multiEcosystemFiles(), { config: {} }),
    );
    const second = await dependenciesScanner.scan(
      contextFor('/fake-root', multiEcosystemFiles(), { config: {} }),
    );

    expect(first.length).toBeGreaterThan(3); // several D002s plus at least one D003
    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
  });

  it('produces byte-identical output across two independent runs with a configured data source', async () => {
    const config = { dataSource: 'file', advisoryDbPath: ADVISORY_DB };
    const first = await dependenciesScanner.scan(
      contextFor('/fake-root', multiEcosystemFiles(), { config }),
    );
    const second = await dependenciesScanner.scan(
      contextFor('/fake-root', multiEcosystemFiles(), { config }),
    );

    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
  });

  it('is already sorted the way core sortFindings would sort it (severity, then file, then line, then ruleId)', async () => {
    const findings = await dependenciesScanner.scan(
      contextFor('/fake-root', multiEcosystemFiles(), {
        config: { dataSource: 'file', advisoryDbPath: ADVISORY_DB },
      }),
    );
    expect(findings).toEqual(sortFindings(findings));
  });
});

describe('cancellation', () => {
  it('rejects immediately when the signal is already aborted', async () => {
    const controller = new AbortController();
    controller.abort();
    const ref = fileRef(fixturePath('go', 'well-formed', 'go.mod'), 'go.mod');
    const context = contextFor('/fake-root', [ref], { signal: controller.signal });
    await expect(dependenciesScanner.scan(context)).rejects.toThrow();
  });

  it('checks cancellation per file and stops processing once the signal is aborted mid-scan', async () => {
    const controller = new AbortController();
    const files = [
      fileRef(fixturePath('go', 'well-formed', 'go.mod'), 'a/go.mod'),
      fileRef(fixturePath('go', 'empty', 'go.mod'), 'b/go.mod'),
      fileRef(fixturePath('go', 'well-formed', 'go.mod'), 'c/go.mod'),
    ];
    const readOrder: string[] = [];
    const context: ScanContext = {
      rootDir: '/fake-root',
      files,
      config: {},
      signal: controller.signal,
      logger: noopLogger,
      readFile: async (ref) => {
        readOrder.push(ref.relPath);
        if (ref.relPath === 'b/go.mod') controller.abort();
        return readFile(ref.absPath, 'utf8');
      },
    };

    await expect(dependenciesScanner.scan(context)).rejects.toThrow();
    // c/go.mod is never reached: the abort raised during b/go.mod's read is
    // observed at the top of the next loop iteration.
    expect(readOrder).toEqual(['a/go.mod', 'b/go.mod']);
  });
});
