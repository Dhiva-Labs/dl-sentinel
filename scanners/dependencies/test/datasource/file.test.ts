import { describe, expect, it } from 'vitest';
import { FileDataSource } from '../../src/datasource/file.js';
import { fixturePath } from '../support.js';

describe('FileDataSource', () => {
  it('returns advisories matching the requested (ecosystem, name) pairs, ignoring version', () => {
    const source = new FileDataSource(fixturePath('advisory-db', 'valid.json'));
    return source
      .query([{ ecosystem: 'npm', name: 'lodash', version: '4.17.15' }])
      .then((advisories) => {
        expect(advisories.map((a) => a.id).sort()).toEqual([
          'GHSA-35jh-r3h4-6jhm',
          'GHSA-p6mc-m468-83gw',
        ]);
        for (const advisory of advisories) {
          expect(advisory.ecosystem).toBe('npm');
          expect(advisory.name).toBe('lodash');
        }
      });
  });

  it('returns the union of matches across every requested package, deduplicated by nothing extra needed (distinct ids)', async () => {
    const source = new FileDataSource(fixturePath('advisory-db', 'valid.json'));
    const advisories = await source.query([
      { ecosystem: 'npm', name: 'lodash', version: '4.17.15' },
      { ecosystem: 'npm', name: 'minimist', version: '1.2.0' },
    ]);
    expect(advisories.map((a) => a.id).sort()).toEqual([
      'GHSA-35jh-r3h4-6jhm',
      'GHSA-p6mc-m468-83gw',
      'GHSA-xvch-5gv4-984h',
    ]);
  });

  it('returns an empty array for a package with no matching advisories', async () => {
    const source = new FileDataSource(fixturePath('advisory-db', 'valid.json'));
    const advisories = await source.query([
      { ecosystem: 'npm', name: 'no-such-package', version: '1.0.0' },
    ]);
    expect(advisories).toEqual([]);
  });

  it('returns an empty array immediately for an empty package list (without needing a match)', async () => {
    const source = new FileDataSource(fixturePath('advisory-db', 'valid.json'));
    expect(await source.query([])).toEqual([]);
  });

  it('does not cross ecosystems: a pip package never matches an npm advisory of the same name', async () => {
    const source = new FileDataSource(fixturePath('advisory-db', 'valid.json'));
    const advisories = await source.query([{ ecosystem: 'go', name: 'lodash', version: '1.0.0' }]);
    expect(advisories).toEqual([]);
  });

  it('throws a clear error for a missing database file', async () => {
    const source = new FileDataSource(fixturePath('advisory-db', 'does-not-exist.json'));
    await expect(source.query([{ ecosystem: 'npm', name: 'x', version: '1.0.0' }])).rejects.toThrow(
      /does-not-exist\.json/,
    );
  });

  it('throws a clear error for invalid JSON', async () => {
    const source = new FileDataSource(fixturePath('advisory-db', 'invalid-json.json'));
    await expect(source.query([{ ecosystem: 'npm', name: 'x', version: '1.0.0' }])).rejects.toThrow(
      /not valid JSON/,
    );
  });

  it('throws a clear error when the top-level shape is not an array', async () => {
    const source = new FileDataSource(fixturePath('advisory-db', 'invalid-shape.json'));
    await expect(source.query([{ ecosystem: 'npm', name: 'x', version: '1.0.0' }])).rejects.toThrow(
      /must be a JSON array/,
    );
  });

  it('throws a clear error for an entry with an invalid field (bad severity)', async () => {
    const source = new FileDataSource(fixturePath('advisory-db', 'invalid-entry.json'));
    await expect(source.query([{ ecosystem: 'npm', name: 'x', version: '1.0.0' }])).rejects.toThrow(
      /severity must be one of/,
    );
  });

  it('re-validates on every call: an invalid database still throws even when the package list is empty', async () => {
    const source = new FileDataSource(fixturePath('advisory-db', 'invalid-json.json'));
    await expect(source.query([])).rejects.toThrow(/not valid JSON/);
  });
});
