import { LineCounter, parseDocument, isMap, isSeq, isScalar } from 'yaml';
import type { Document } from 'yaml';
import type { Locator } from './internal-types.js';
import type { PathSegment } from './pointer.js';

export interface YamlParseResult {
  ok: boolean;
  root?: Record<string, unknown>;
  locator?: Locator;
  error?: string;
}

/**
 * Parse YAML text into plain JS data plus a best-effort line/column locator.
 * Never throws: parse errors are reported via `ok: false`.
 */
export function parseYamlDocument(text: string): YamlParseResult {
  let doc: Document;
  try {
    const lineCounter = new LineCounter();
    doc = parseDocument(text, { lineCounter, uniqueKeys: false });
    if (doc.errors.length > 0) {
      return { ok: false, error: doc.errors[0]?.message ?? 'YAML parse error' };
    }
    const root = doc.toJS() ?? {};
    if (typeof root !== 'object' || root === null || Array.isArray(root)) {
      return { ok: false, error: 'YAML document root is not a mapping' };
    }
    const locator: Locator = {
      locate(path: readonly PathSegment[]): { line?: number; column?: number } {
        const range = findNodeRange(doc.contents, path);
        if (!range) return {};
        const pos = lineCounter.linePos(range[0]);
        return { line: pos.line, column: pos.col };
      },
    };
    return { ok: true, root: root as Record<string, unknown>, locator };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

/**
 * Walk the YAML CST (not the resolved JS value) following `path`, returning the
 * range of the final segment's key node when available, else its value node.
 * Best-effort: returns undefined for anything not found or not addressable
 * (e.g. array index out of range, path through a scalar).
 */
function findNodeRange(
  root: unknown,
  path: readonly PathSegment[],
): [number, number, number] | undefined {
  let current: unknown = root;
  let keyRange: [number, number, number] | undefined;
  let valueRange: [number, number, number] | undefined;
  for (const seg of path) {
    if (isMap(current)) {
      const pair = current.items.find((p) => {
        const k = p.key;
        const keyValue = isScalar(k) ? k.value : k;
        return keyValue === seg;
      });
      if (!pair) return undefined;
      keyRange =
        isScalar(pair.key) || isMap(pair.key) || isSeq(pair.key)
          ? (pair.key.range ?? undefined)
          : undefined;
      const value = pair.value;
      valueRange =
        isScalar(value) || isMap(value) || isSeq(value) ? (value.range ?? undefined) : undefined;
      current = value;
    } else if (isSeq(current)) {
      if (typeof seg !== 'number') return undefined;
      const item: unknown = current.items[seg];
      if (item === undefined) return undefined;
      keyRange = undefined;
      valueRange =
        isScalar(item) || isMap(item) || isSeq(item) ? (item.range ?? undefined) : undefined;
      current = item;
    } else {
      return undefined;
    }
  }
  return keyRange ?? valueRange;
}

/** A locator that never resolves a position (used for JSON-sourced documents). */
export const noopLocator: Locator = {
  locate(): { line?: number; column?: number } {
    return {};
  },
};
