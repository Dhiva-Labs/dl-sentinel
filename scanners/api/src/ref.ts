import { isPlainObject } from './util.js';

/** True for OpenAPI/Swagger schema-object-shaped nodes carrying a `$ref` string. */
export function isRefNode(node: unknown): node is { $ref: string } {
  return isPlainObject(node) && typeof node.$ref === 'string';
}

/**
 * True when a $ref string points within the same document (a JSON pointer
 * fragment like "#/components/schemas/User"). External file paths and network
 * URLs are never followed (per scanner rules: no network, no file refs).
 */
export function isLocalRef(ref: string): boolean {
  return ref.startsWith('#/') || ref === '#';
}

function decodeToken(token: string): string {
  return token.replace(/~1/g, '/').replace(/~0/g, '~');
}

/**
 * Resolve a local ($ref: "#/a/b/c") JSON pointer against the document root.
 * Returns undefined when the ref is external/network, malformed, or does not
 * resolve to anything (never throws).
 */
export function resolveLocalRef(root: unknown, ref: string): unknown {
  if (!isLocalRef(ref)) return undefined;
  const pointer = ref.slice(1); // drop leading '#'
  if (pointer === '') return root;
  if (!pointer.startsWith('/')) return undefined;
  const tokens = pointer.slice(1).split('/').map(decodeToken);
  let current: unknown = root;
  for (const token of tokens) {
    if (Array.isArray(current)) {
      const index = Number(token);
      if (!Number.isInteger(index) || index < 0 || index >= current.length) return undefined;
      current = current[index];
    } else if (isPlainObject(current)) {
      if (!Object.prototype.hasOwnProperty.call(current, token)) return undefined;
      current = current[token];
    } else {
      return undefined;
    }
  }
  return current;
}
