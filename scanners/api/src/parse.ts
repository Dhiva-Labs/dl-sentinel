import type { ApiKind, ParsedDoc } from './internal-types.js';
import { isPlainObject } from './util.js';
import { noopLocator, parseYamlDocument } from './yaml-location.js';

export type ParseOutcome =
  { status: 'ok'; doc: ParsedDoc } | { status: 'skip' } | { status: 'error'; message: string };

function detectFormat(relPath: string): 'yaml' | 'json' {
  return /\.json$/i.test(relPath) ? 'json' : 'yaml';
}

function detectKind(root: Record<string, unknown>): ApiKind | undefined {
  const openapi = root.openapi;
  if (typeof openapi === 'string' && openapi.trim().startsWith('3')) {
    return 'openapi3';
  }
  const swagger = root.swagger;
  if (typeof swagger === 'string' && swagger.trim().startsWith('2')) {
    return 'swagger2';
  }
  const info = root.info;
  if (isPlainObject(info)) {
    if (typeof info._postman_id === 'string' && info._postman_id.length > 0) {
      return 'postman2';
    }
    if (typeof info.schema === 'string' && /getpostman\.com/i.test(info.schema)) {
      return 'postman2';
    }
  }
  return undefined;
}

/**
 * Parse a candidate file's text and self-identify it as OpenAPI 3, Swagger 2,
 * or a Postman v2 collection. Never throws:
 * - malformed JSON/YAML -> { status: 'error' } (caller should logger.warn + skip)
 * - well-formed but not an API document -> { status: 'skip' } (silent, expected
 *   for generic *.{yml,yaml,json} files that happen to match the glob)
 */
export function parseCandidate(relPath: string, text: string): ParseOutcome {
  const format = detectFormat(relPath);
  if (format === 'json') {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch (err) {
      return { status: 'error', message: err instanceof Error ? err.message : String(err) };
    }
    if (!isPlainObject(parsed)) return { status: 'skip' };
    const kind = detectKind(parsed);
    if (!kind) return { status: 'skip' };
    return { status: 'ok', doc: { kind, format: 'json', root: parsed, locator: noopLocator } };
  }

  const result = parseYamlDocument(text);
  if (!result.ok || !result.root || !result.locator) {
    return { status: 'error', message: result.error ?? 'YAML parse error' };
  }
  const kind = detectKind(result.root);
  if (!kind) return { status: 'skip' };
  return {
    status: 'ok',
    doc: { kind, format: 'yaml', root: result.root, locator: result.locator },
  };
}
