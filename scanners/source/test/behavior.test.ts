import { readFile } from 'node:fs/promises';
import { describe, expect, it } from 'vitest';
import { noopLogger } from '@dl-sentinel/core';
import type { FileRef, ScanContext } from '@dl-sentinel/core';
import { sourceScanner } from '../src/index.js';
import { makeScanContext } from '../../../tests/support/index.js';
import { fileRefFor, localFixturePath } from './testUtil.js';

async function scanOne(relPath: string) {
  const ctx = makeScanContext(localFixturePath(), [fileRefFor(relPath)]);
  return sourceScanner.scan(ctx);
}

function contextWithReadFile(
  files: readonly FileRef[],
  readFileImpl: ScanContext['readFile'],
): ScanContext {
  return {
    rootDir: localFixturePath(),
    files,
    config: {},
    signal: new AbortController().signal,
    logger: noopLogger,
    readFile: readFileImpl,
  };
}

describe('comment and docstring handling', () => {
  it('does not flag a dangerous pattern hidden behind a // or # line comment', async () => {
    const jsFindings = await scanOne('comment-skip/commented-out.js');
    expect(jsFindings).toHaveLength(0);

    const pyFindings = await scanOne('comment-skip/commented-out.py');
    expect(pyFindings).toHaveLength(0);
  });

  it('does not flag a dangerous pattern inside a /** ... */ block comment', async () => {
    const findings = await scanOne('comment-skip/block-comment.js');
    expect(findings).toHaveLength(0);
  });

  it('does not flag a dangerous pattern inside a triple-quoted docstring, including lines that do not themselves start with a marker', async () => {
    const findings = await scanOne('comment-skip/docstring.py');
    expect(findings).toHaveLength(0);
  });
});

describe('determinism', () => {
  it('produces identical findings across repeated runs, regardless of input file order', async () => {
    const files = [
      fileRefFor('c001/js-positive.js'),
      fileRefFor('c003/py-positive.py'),
      fileRefFor('c008/go-positive.go'),
    ];
    const ctx1 = makeScanContext(localFixturePath(), files);
    const ctx2 = makeScanContext(localFixturePath(), [...files].reverse());

    const [run1, run2, run3] = await Promise.all([
      sourceScanner.scan(ctx1),
      sourceScanner.scan(ctx1),
      sourceScanner.scan(ctx2),
    ]);

    expect(run1).toEqual(run2);
    // Reversing the input file order must not change the (sorted) output.
    expect(run1).toEqual(run3);
    expect(run1.length).toBeGreaterThan(0);
  });
});

describe('cancellation', () => {
  it('throws without reading any file when the signal is already aborted', async () => {
    const controller = new AbortController();
    controller.abort();
    const ctx: ScanContext = {
      rootDir: localFixturePath(),
      files: [fileRefFor('c001/js-positive.js')],
      config: {},
      signal: controller.signal,
      logger: noopLogger,
      readFile: async (ref) => {
        throw new Error(`readFile should not be called once aborted, got ${ref.relPath}`);
      },
    };

    await expect(sourceScanner.scan(ctx)).rejects.toThrow();
  });

  it('stops before the second file once cancellation arrives mid-scan', async () => {
    const controller = new AbortController();
    const files = [fileRefFor('c001/js-positive.js'), fileRefFor('c003/py-positive.py')];
    let readCount = 0;
    const ctx: ScanContext = {
      rootDir: localFixturePath(),
      files,
      config: {},
      signal: controller.signal,
      logger: noopLogger,
      readFile: async (ref) => {
        readCount++;
        const content = await readFile(ref.absPath, 'utf8');
        // Simulate cancellation arriving right after the first file is read.
        controller.abort();
        return content;
      },
    };

    await expect(sourceScanner.scan(ctx)).rejects.toThrow();
    expect(readCount).toBe(1);
  });
});

describe('empty and binary-ish content', () => {
  it('returns no findings and does not throw for an empty file', async () => {
    const findings = await scanOne('misc/empty.js');
    expect(findings).toEqual([]);
  });

  it('does not throw on content containing NUL bytes and other non-text-ish bytes', async () => {
    const weirdBytes = [0x00, 0x01, 0xff, 0xfe, 0x00, 0x07]
      .map((c) => String.fromCharCode(c))
      .join('');
    const weird = `const x = 1;\n${weirdBytes}\nconst y = 2;\n`.repeat(20);
    const ref = fileRefFor('c001/js-positive.js'); // path is irrelevant; content is stubbed below
    const ctx = contextWithReadFile([ref], async () => weird);

    await expect(sourceScanner.scan(ctx)).resolves.toBeInstanceOf(Array);
  });

  it('does not throw on a single absurdly long line', async () => {
    const longLine = `const cmd = 'x' + ${'"a" + '.repeat(5000)}"end";`;
    const ref = fileRefFor('c001/js-positive.js');
    const ctx = contextWithReadFile([ref], async () => longLine);

    await expect(sourceScanner.scan(ctx)).resolves.toBeInstanceOf(Array);
  });
});
