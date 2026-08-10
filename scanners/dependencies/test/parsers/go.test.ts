import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { parseGoMod } from '../../src/parsers/go.js';
import { createRecordingLogger, fixturePath } from '../support.js';

function read(...segments: string[]): string {
  return readFileSync(fixturePath(...segments), 'utf8');
}

describe('parseGoMod', () => {
  it('parses the single-line require and the block form, marking "// indirect" as transitive', () => {
    const content = read('go', 'well-formed', 'go.mod');
    const logger = createRecordingLogger();
    const records = parseGoMod('go.mod', content, logger);

    expect(records).toEqual([
      {
        ecosystem: 'go',
        name: 'github.com/dl-fixture/vulnpkg',
        version: 'v1.2.3',
        versionKind: 'exact',
        direct: true,
        sourceFile: 'go.mod',
        line: 5,
      },
      {
        ecosystem: 'go',
        name: 'github.com/dl-fixture/indirectpkg',
        version: 'v0.5.0',
        versionKind: 'exact',
        direct: false,
        sourceFile: 'go.mod',
        line: 8,
      },
      {
        ecosystem: 'go',
        name: 'github.com/dl-fixture/pseudopkg',
        version: 'v0.0.0-20210101000000-abcdef123456',
        versionKind: 'exact',
        direct: true,
        sourceFile: 'go.mod',
        line: 9,
      },
      {
        ecosystem: 'go',
        name: 'github.com/dl-fixture/prereleasepkg',
        version: 'v1.0.0-beta.1',
        versionKind: 'exact',
        direct: true,
        sourceFile: 'go.mod',
        line: 10,
      },
    ]);
    expect(logger.warnings).toEqual([]);
  });

  it('returns no records for a go.mod with no require directives (empty)', () => {
    const content = read('go', 'empty', 'go.mod');
    const logger = createRecordingLogger();
    expect(parseGoMod('go.mod', content, logger)).toEqual([]);
    expect(logger.warnings).toEqual([]);
  });

  it('warns on an unrecognized line inside a require block but still parses the rest (malformed)', () => {
    const content = read('go', 'malformed', 'go.mod');
    const logger = createRecordingLogger();
    const records = parseGoMod('go.mod', content, logger);

    expect(records).toEqual([
      {
        ecosystem: 'go',
        name: 'github.com/dl-fixture/goodpkg',
        version: 'v1.0.0',
        versionKind: 'exact',
        direct: true,
        sourceFile: 'go.mod',
        line: 7,
      },
    ]);
    expect(logger.warnings.length).toBe(1);
  });

  it('recognizes any trailing comment text as indirect only when it says so', () => {
    const content =
      'module x\n\ngo 1.21\n\nrequire (\n\tgithub.com/a/b v1.0.0 // pinned for CI, see issue #123\n)\n';
    const records = parseGoMod('go.mod', content, createRecordingLogger());
    expect(records).toEqual([
      {
        ecosystem: 'go',
        name: 'github.com/a/b',
        version: 'v1.0.0',
        versionKind: 'exact',
        direct: true,
        sourceFile: 'go.mod',
        line: 6,
      },
    ]);
  });
});
