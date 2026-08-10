/**
 * Shared YAML plumbing for the compose and Kubernetes rule modules.
 *
 * Strategy: parse with the `yaml` package's `Document` API (never the
 * throwing `parse()` shorthand) so a malformed document surfaces as
 * `doc.errors` instead of an exception, convert to plain JS once per
 * document for easy logic (`doc.toJS()`), and fall back to the AST
 * (`doc.getIn(path, true)`) only when a specific finding needs a source
 * line number. This keeps rule logic readable while still recovering
 * best-effort positions.
 */
import { LineCounter, parseAllDocuments } from 'yaml';
import type { Document, EmptyStream } from 'yaml';

export interface ParsedYaml {
  /** Every document in the stream that parsed cleanly and isn't empty/null. */
  documents: Document.Parsed[];
  lineCounter: LineCounter;
}

/**
 * Parse a (possibly multi-document) YAML file. Returns `undefined` when
 * nothing usable could be recovered — an empty file, a stream of only
 * `---` separators, or a document whose errors make its tree untrustworthy
 * — so the caller can log a warning and skip the file, never throw.
 */
export function parseYamlFile(text: string): ParsedYaml | undefined {
  const lineCounter = new LineCounter();
  // Annotated explicitly (rather than via `ReturnType<typeof parseAllDocuments>`)
  // because that generic function's return type distributes over the
  // `ParsedNode` union for its defaulted type parameter, which does not
  // structurally match `Document.Parsed[]` — see the yaml package's own types.
  let parsed: Document.Parsed[] | EmptyStream;
  try {
    parsed = parseAllDocuments(text, { lineCounter });
  } catch {
    return undefined;
  }
  if ('empty' in parsed) return undefined;

  const documents = parsed.filter((doc) => doc.errors.length === 0 && doc.contents != null);
  if (documents.length === 0) return undefined;
  return { documents, lineCounter };
}

/** 1-based `{ line, col }` for a character offset, or undefined if unknown. */
export function positionFor(
  lineCounter: LineCounter,
  offset: number | undefined,
): { line: number; col: number } | undefined {
  if (offset === undefined || offset < 0) return undefined;
  const pos = lineCounter.linePos(offset);
  return pos.line > 0 ? pos : undefined;
}

/**
 * Best-effort source line for a value at `path` within `doc`. Returns
 * undefined rather than a guess when the path can't be resolved to a node
 * with a recorded range (e.g. the value was synthesized, not parsed).
 */
export function lineForPath(
  doc: Document,
  lineCounter: LineCounter,
  path: ReadonlyArray<string | number>,
): number | undefined {
  try {
    const node = doc.getIn(path as (string | number)[], true) as
      { range?: [number, number, number] | null } | null | undefined;
    const offset = node?.range?.[0];
    return positionFor(lineCounter, offset)?.line;
  } catch {
    return undefined;
  }
}

/**
 * Best-effort evidence for a value at `path`: the actual source line if a
 * range can be resolved, otherwise a synthesized fallback description (still
 * useful evidence, just without a line number attached).
 */
export function evidenceAt(params: {
  doc: Document;
  lineCounter: LineCounter;
  lines: readonly string[];
  path: ReadonlyArray<string | number>;
  fallback: string;
}): { line?: number; evidence: string } {
  const line = lineForPath(params.doc, params.lineCounter, params.path);
  if (line !== undefined) {
    const text = params.lines[line - 1]?.trim();
    return { line, evidence: text && text.length > 0 ? text : params.fallback };
  }
  return { evidence: params.fallback };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** A Kubernetes manifest document declares both `kind` and `apiVersion`. */
export function isKubernetesDoc(value: unknown): value is Record<string, unknown> {
  return (
    isPlainObject(value) && typeof value.kind === 'string' && typeof value.apiVersion === 'string'
  );
}

/** A compose file's defining shape is a top-level `services` map. */
export function isComposeDoc(value: unknown): value is Record<string, unknown> {
  return isPlainObject(value) && isPlainObject(value.services);
}
