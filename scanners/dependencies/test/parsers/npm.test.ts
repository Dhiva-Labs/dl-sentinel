import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parsePackageJson, parsePackageLock } from '../../src/parsers/npm.js';
import { createRecordingLogger, fixturePath } from '../support.js';

function read(...segments: string[]): string {
  return readFileSync(fixturePath(...segments), 'utf8');
}

describe('parsePackageJson', () => {
  it('parses dependencies and devDependencies as direct, range records with best-effort line numbers', () => {
    const content = read('npm', 'well-formed', 'package.json');
    const logger = createRecordingLogger();
    const records = parsePackageJson('package.json', content, logger);

    expect(records).toEqual([
      {
        ecosystem: 'npm',
        name: 'dl-fixture-devpkg',
        version: '>=2.0.0',
        versionKind: 'range',
        direct: true,
        sourceFile: 'package.json',
        line: 9,
      },
      {
        ecosystem: 'npm',
        name: 'dl-fixture-vulnpkg',
        version: '^1.2.0',
        versionKind: 'range',
        direct: true,
        sourceFile: 'package.json',
        line: 5,
      },
      {
        ecosystem: 'npm',
        name: 'left-pad',
        version: '1.3.0',
        versionKind: 'range',
        direct: true,
        sourceFile: 'package.json',
        line: 6,
      },
    ]);
    expect(logger.warnings).toEqual([]);
  });

  it('returns no records and does not throw for a package.json with no dependency fields (empty)', () => {
    const content = read('npm', 'empty', 'package.json');
    const logger = createRecordingLogger();
    expect(parsePackageJson('package.json', content, logger)).toEqual([]);
    expect(logger.warnings).toEqual([]);
  });

  it('warns and returns no records for invalid JSON (malformed), without throwing', () => {
    const content = read('npm', 'malformed', 'package.json');
    const logger = createRecordingLogger();
    expect(() => parsePackageJson('package.json', content, logger)).not.toThrow();
    expect(parsePackageJson('package.json', content, logger)).toEqual([]);
    expect(logger.warnings.length).toBeGreaterThan(0);
    expect(logger.warnings[0]).toContain('package.json');
  });

  it('warns and skips a non-object dependencies field rather than crashing', () => {
    const content = JSON.stringify({ name: 'x', dependencies: 'not-an-object' });
    const logger = createRecordingLogger();
    expect(parsePackageJson('package.json', content, logger)).toEqual([]);
    expect(logger.warnings.length).toBe(1);
  });

  it('warns and skips a non-string version value rather than crashing', () => {
    const content = JSON.stringify({ name: 'x', dependencies: { foo: 123 } });
    const logger = createRecordingLogger();
    expect(parsePackageJson('package.json', content, logger)).toEqual([]);
    expect(logger.warnings.length).toBe(1);
  });

  it('warns and returns no records for a top-level JSON array', () => {
    const logger = createRecordingLogger();
    expect(parsePackageJson('package.json', '[]', logger)).toEqual([]);
    expect(logger.warnings.length).toBe(1);
  });
});

describe('parsePackageLock', () => {
  it('parses the packages map into exact records, marking direct vs transitive and finding unique-key line numbers', () => {
    const content = read('npm', 'well-formed', 'package-lock.json');
    const logger = createRecordingLogger();
    const records = parsePackageLock('package-lock.json', content, logger);

    expect(records).toEqual([
      {
        ecosystem: 'npm',
        name: 'dl-fixture-devpkg',
        version: '2.5.0',
        versionKind: 'exact',
        direct: true,
        sourceFile: 'package-lock.json',
        line: 26,
      },
      {
        ecosystem: 'npm',
        name: 'dl-fixture-transitive',
        version: '0.9.0',
        versionKind: 'exact',
        direct: false,
        sourceFile: 'package-lock.json',
        line: 30,
      },
      {
        ecosystem: 'npm',
        name: 'dl-fixture-vulnpkg',
        version: '1.2.3',
        versionKind: 'exact',
        direct: true,
        sourceFile: 'package-lock.json',
        line: 18,
      },
      {
        ecosystem: 'npm',
        name: 'left-pad',
        version: '1.3.0',
        versionKind: 'exact',
        direct: true,
        sourceFile: 'package-lock.json',
        line: 22,
      },
    ]);
    expect(logger.warnings).toEqual([]);
  });

  it('marks a nested node_modules path as transitive even when its name coincidentally matches nothing declared', () => {
    const content = read('npm', 'well-formed', 'package-lock.json');
    const records = parsePackageLock('package-lock.json', content, createRecordingLogger());
    const transitive = records.find((r) => r.name === 'dl-fixture-transitive');
    expect(transitive?.direct).toBe(false);
  });

  it('warns and returns no records when there is no "packages" map (lockfileVersion 1)', () => {
    const content = read('npm', 'malformed', 'package-lock.json');
    const logger = createRecordingLogger();
    expect(parsePackageLock('package-lock.json', content, logger)).toEqual([]);
    expect(logger.warnings.length).toBe(1);
  });

  it('warns and returns no records for invalid JSON, without throwing', () => {
    const logger = createRecordingLogger();
    expect(() => parsePackageLock('package-lock.json', '{ broken', logger)).not.toThrow();
    expect(parsePackageLock('package-lock.json', '{ broken', logger)).toEqual([]);
  });

  it('skips packages map entries with no version (e.g. a link: workspace entry)', () => {
    const content = JSON.stringify({
      packages: {
        '': { dependencies: { foo: '1.0.0' } },
        'node_modules/foo': { resolved: 'link:../foo' },
      },
    });
    const records = parsePackageLock('package-lock.json', content, createRecordingLogger());
    expect(records).toEqual([]);
  });
});
