/** Small shared helpers used across the api scanner. Not exported from the package. */

export function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function isNonEmptyArray(value: unknown): value is unknown[] {
  return Array.isArray(value) && value.length > 0;
}

export function asString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

/** HTTP methods recognized as operations under an OpenAPI/Swagger path item. */
export const HTTP_METHODS = [
  'get',
  'put',
  'post',
  'delete',
  'options',
  'head',
  'patch',
  'trace',
] as const;

export type HttpMethod = (typeof HTTP_METHODS)[number];

/** Methods considered state-changing for A005. */
export const STATE_CHANGING_METHODS: ReadonlySet<string> = new Set([
  'post',
  'put',
  'patch',
  'delete',
]);

const LOCALHOST_HOSTS = new Set(['localhost', '127.0.0.1', '::1', '0.0.0.0']);

/** True if a hostname is a loopback/local address (used to downgrade A003 severity). */
export function isLocalHost(hostname: string | undefined): boolean {
  if (!hostname) return false;
  const h = hostname.toLowerCase();
  return LOCALHOST_HOSTS.has(h) || h.endsWith('.localhost');
}

/**
 * Best-effort scheme+host extraction from a URL-like string. Returns undefined
 * when the string does not look like an absolute http(s) URL (e.g. a template
 * placeholder such as "{{baseUrl}}/users").
 */
export function parseUrlish(
  raw: string,
): { scheme: string; hostname: string | undefined } | undefined {
  const match = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/([^/?#]*)/.exec(raw);
  if (!match) return undefined;
  const scheme = match[1]?.toLowerCase();
  if (!scheme) return undefined;
  const authority = match[2] ?? '';
  // Strip credentials (user:pass@) and port.
  const hostPart = authority.split('@').pop() ?? '';
  const hostname = hostPart.split(':')[0];
  return { scheme, hostname: hostname && hostname.length > 0 ? hostname : undefined };
}

/** Depth cap shared by every recursive schema/JSON walker in this scanner. */
export const MAX_WALK_DEPTH = 12;
