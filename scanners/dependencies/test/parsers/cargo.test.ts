import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseCargoLock, parseCargoToml } from '../../src/parsers/cargo.js';
import { createRecordingLogger, fixturePath } from '../support.js';

function read(...segments: string[]): string {
  return readFileSync(fixturePath(...segments), 'utf8');
}

describe('parseCargoToml', () => {
  it('parses [dependencies]/[dev-dependencies]/[build-dependencies], both string and table forms, skipping path deps', () => {
    const content = read('cargo', 'well-formed', 'Cargo.toml');
    const logger = createRecordingLogger();
    const records = parseCargoToml('Cargo.toml', content, logger);

    expect(records).toEqual([
      {
        ecosystem: 'cargo',
        name: 'dl-fixture-vulnpkg',
        version: '1.2.3',
        versionKind: 'range',
        direct: true,
        sourceFile: 'Cargo.toml',
        line: 6,
      },
      {
        ecosystem: 'cargo',
        name: 'dl-fixture-rangepkg',
        version: '^0.9.0',
        versionKind: 'range',
        direct: true,
        sourceFile: 'Cargo.toml',
        line: 7,
      },
      // local-thing (line 8, `{ path = "../local-thing" }`) has no registry version: skipped.
      {
        ecosystem: 'cargo',
        name: 'dl-fixture-devpkg',
        version: '2.0.0',
        versionKind: 'range',
        direct: true,
        sourceFile: 'Cargo.toml',
        line: 11,
      },
      {
        ecosystem: 'cargo',
        name: 'dl-fixture-buildpkg',
        version: '>=1.0.0',
        versionKind: 'range',
        direct: true,
        sourceFile: 'Cargo.toml',
        line: 14,
      },
    ]);
    expect(logger.warnings).toEqual([]);
  });

  it('returns no records for a Cargo.toml with only a [package] section (empty)', () => {
    const content = read('cargo', 'empty', 'Cargo.toml');
    const logger = createRecordingLogger();
    expect(parseCargoToml('Cargo.toml', content, logger)).toEqual([]);
    expect(logger.warnings).toEqual([]);
  });

  it('warns on an unrecognized line in a dependency table but still parses the rest (malformed)', () => {
    const content = read('cargo', 'malformed', 'Cargo.toml');
    const logger = createRecordingLogger();
    const records = parseCargoToml('Cargo.toml', content, logger);

    expect(records).toEqual([
      {
        ecosystem: 'cargo',
        name: 'dl-fixture-goodpkg',
        version: '1.0.0',
        versionKind: 'range',
        direct: true,
        sourceFile: 'Cargo.toml',
        line: 7,
      },
    ]);
    expect(logger.warnings.length).toBe(1);
  });

  it('ignores a git dependency table (no registry version)', () => {
    const content =
      '[dependencies]\nfoo = { git = "https://example.invalid/foo.git", branch = "main" }\n';
    const records = parseCargoToml('Cargo.toml', content, createRecordingLogger());
    expect(records).toEqual([]);
  });

  it('ignores target-specific dependency tables it does not model', () => {
    const content = '[target.\'cfg(unix)\'.dependencies]\nfoo = "1.0.0"\n';
    const records = parseCargoToml('Cargo.toml', content, createRecordingLogger());
    expect(records).toEqual([]);
  });
});

describe('parseCargoLock', () => {
  it('parses every [[package]] block (multi-package), defaulting direct to false', () => {
    const content = read('cargo', 'well-formed', 'Cargo.lock');
    const logger = createRecordingLogger();
    const records = parseCargoLock('Cargo.lock', content, logger);

    expect(records).toEqual([
      {
        ecosystem: 'cargo',
        name: 'cargo-fixture',
        version: '0.1.0',
        versionKind: 'exact',
        direct: false,
        sourceFile: 'Cargo.lock',
        line: 6,
      },
      {
        ecosystem: 'cargo',
        name: 'dl-fixture-vulnpkg',
        version: '1.2.3',
        versionKind: 'exact',
        direct: false,
        sourceFile: 'Cargo.lock',
        line: 10,
      },
      {
        ecosystem: 'cargo',
        name: 'dl-fixture-rangepkg',
        version: '0.9.5',
        versionKind: 'exact',
        direct: false,
        sourceFile: 'Cargo.lock',
        line: 15,
      },
      {
        ecosystem: 'cargo',
        name: 'dl-fixture-devpkg',
        version: '2.0.0',
        versionKind: 'exact',
        direct: false,
        sourceFile: 'Cargo.lock',
        line: 20,
      },
      {
        ecosystem: 'cargo',
        name: 'dl-fixture-buildpkg',
        version: '1.4.0',
        versionKind: 'exact',
        direct: false,
        sourceFile: 'Cargo.lock',
        line: 25,
      },
    ]);
    expect(logger.warnings).toEqual([]);
  });

  it('returns just the root package for a Cargo.lock with no external dependencies (empty)', () => {
    const content = read('cargo', 'empty', 'Cargo.lock');
    const logger = createRecordingLogger();
    expect(parseCargoLock('Cargo.lock', content, logger)).toEqual([
      {
        ecosystem: 'cargo',
        name: 'empty-fixture',
        version: '0.1.0',
        versionKind: 'exact',
        direct: false,
        sourceFile: 'Cargo.lock',
        line: 5,
      },
    ]);
  });

  it('warns and skips a [[package]] block missing a version, but still parses the next block (malformed)', () => {
    const content = read('cargo', 'malformed', 'Cargo.lock');
    const logger = createRecordingLogger();
    const records = parseCargoLock('Cargo.lock', content, logger);

    expect(records).toEqual([
      {
        ecosystem: 'cargo',
        name: 'dl-fixture-goodpkg',
        version: '1.0.0',
        versionKind: 'exact',
        direct: false,
        sourceFile: 'Cargo.lock',
        line: 9,
      },
    ]);
    expect(logger.warnings.length).toBe(1);
    expect(logger.warnings[0]).toContain('broken-fixture');
  });

  it('does not crash on an empty string', () => {
    expect(parseCargoLock('Cargo.lock', '', createRecordingLogger())).toEqual([]);
  });
});
