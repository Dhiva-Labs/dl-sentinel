import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseRequirementsTxt } from '../../src/parsers/pip.js';
import { createRecordingLogger, fixturePath } from '../support.js';

function read(...segments: string[]): string {
  return readFileSync(fixturePath(...segments), 'utf8');
}

describe('parseRequirementsTxt', () => {
  it('parses == pins as exact and >=/<= specs as range, skipping comments/options/unpinned/unsupported lines', () => {
    const content = read('pip', 'well-formed', 'requirements.txt');
    const logger = createRecordingLogger();
    const records = parseRequirementsTxt('requirements.txt', content, logger);

    expect(records).toEqual([
      {
        ecosystem: 'pip',
        name: 'dl-fixture-vulnpkg',
        version: '1.2.3',
        versionKind: 'exact',
        direct: true,
        sourceFile: 'requirements.txt',
        line: 2,
      },
      {
        ecosystem: 'pip',
        name: 'dl-fixture-rangepkg',
        version: '>=2.0.0',
        versionKind: 'range',
        direct: true,
        sourceFile: 'requirements.txt',
        line: 3,
      },
      {
        ecosystem: 'pip',
        name: 'requests',
        version: '2.6.0',
        versionKind: 'exact',
        direct: true,
        sourceFile: 'requirements.txt',
        line: 6,
      },
    ]);
    // unpinned-package (line 4): no version, nothing to check, no warning.
    // dl-fixture-excluded~=1.0.0 (line 5): ~= unsupported, warns.
    // django>=2.0,<3.0 (line 7): compound spec unsupported, warns.
    // -e ... (line 8): an option line, silently skipped, no warning.
    expect(logger.warnings.length).toBe(2);
  });

  it('returns no records for an empty file', () => {
    const content = read('pip', 'empty', 'requirements.txt');
    const logger = createRecordingLogger();
    expect(parseRequirementsTxt('requirements.txt', content, logger)).toEqual([]);
    expect(logger.warnings).toEqual([]);
  });

  it('survives a malformed file, warning on garbage lines but still extracting the good ones', () => {
    const content = read('pip', 'malformed', 'requirements.txt');
    const logger = createRecordingLogger();
    const records = parseRequirementsTxt('requirements.txt', content, logger);

    expect(records).toEqual([
      {
        ecosystem: 'pip',
        name: 'dl-fixture-vulnpkg',
        version: '9.9.9',
        versionKind: 'exact',
        direct: true,
        sourceFile: 'requirements.txt',
        line: 2,
      },
      {
        ecosystem: 'pip',
        name: 'left-pad',
        version: '1.3.0',
        versionKind: 'exact',
        direct: true,
        sourceFile: 'requirements.txt',
        line: 7,
      },
    ]);
    expect(logger.warnings.length).toBe(2); // line 1 and line 6
  });

  it('strips environment markers after ";"', () => {
    const logger = createRecordingLogger();
    const records = parseRequirementsTxt(
      'requirements.txt',
      'dl-fixture-vulnpkg==1.0.0; python_version < "3.8"\n',
      logger,
    );
    expect(records).toEqual([
      {
        ecosystem: 'pip',
        name: 'dl-fixture-vulnpkg',
        version: '1.0.0',
        versionKind: 'exact',
        direct: true,
        sourceFile: 'requirements.txt',
        line: 1,
      },
    ]);
  });

  it('strips extras from the package name', () => {
    const records = parseRequirementsTxt(
      'requirements.txt',
      'dl-fixture-vulnpkg[security]==1.0.0\n',
      createRecordingLogger(),
    );
    expect(records[0]?.name).toBe('dl-fixture-vulnpkg');
    expect(records[0]?.version).toBe('1.0.0');
  });

  it('does not crash on a completely empty string with no trailing newline', () => {
    expect(parseRequirementsTxt('requirements.txt', '', createRecordingLogger())).toEqual([]);
  });
});
