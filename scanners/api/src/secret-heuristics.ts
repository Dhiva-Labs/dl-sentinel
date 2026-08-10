import { shannonEntropy } from '@dl-sentinel/core';
import type { Confidence } from '@dl-sentinel/core';

/** Named, high-confidence secret shapes (vendor token formats, JWTs). Unanchored: usable against free text. */
const NAMED_TOKEN_PATTERNS: RegExp[] = [
  /AKIA[0-9A-Z]{16}/, // AWS access key id
  /gh[pousr]_[A-Za-z0-9]{20,}/, // GitHub tokens (personal/oauth/user/server/refresh)
  /xox[baprs]-[A-Za-z0-9-]{10,}/, // Slack tokens
  /AIza[0-9A-Za-z_-]{35}/, // Google API key
  /(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{16,}/, // Stripe keys
  /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/, // JWT
];

const GENERIC_OPAQUE_TOKEN = /^[A-Za-z0-9_-]{32,}$/;
const GENERIC_ENTROPY_THRESHOLD = 3.2;

/** Search free text (e.g. a saved response body) for the first named token-shape match. */
export function findTokenInText(text: string): string | undefined {
  for (const pattern of NAMED_TOKEN_PATTERNS) {
    const match = pattern.exec(text);
    if (match) return match[0];
  }
  return undefined;
}

/**
 * Classify a standalone value (a variable or header value, expected to BE the
 * secret rather than contain one among other text) as a token shape or not.
 */
export function classifyStandaloneValue(value: string): { confidence: Confidence } | undefined {
  const trimmed = value.trim();
  if (findTokenInText(trimmed)) return { confidence: 'high' };
  if (GENERIC_OPAQUE_TOKEN.test(trimmed) && shannonEntropy(trimmed) > GENERIC_ENTROPY_THRESHOLD) {
    return { confidence: 'medium' };
  }
  return undefined;
}

const PLACEHOLDER_RX =
  /^(\{\{.*\}\}|<.*>|x{3,}|changeme|your[_-]?\w*|my[_-]?\w*|example\w*|sample\w*|placeholder\w*|dummy\w*|fake\w*|test\w*|redacted|\*{3,}|null|undefined|todo)$/i;

/** True when a value looks like a non-secret placeholder rather than a real credential. */
export function looksLikePlaceholder(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length === 0) return true;
  return PLACEHOLDER_RX.test(trimmed);
}

/**
 * True when a value contains a Postman "{{variable}}" template reference —
 * including common partial forms like "Bearer {{token}}" that do not match
 * looksLikePlaceholder's whole-string check. Such values are parameterized,
 * not literal secrets; the referenced variable is evaluated on its own.
 */
export function hasTemplateReference(value: string): boolean {
  return /\{\{\s*[\w.:-]+\s*\}\}/.test(value);
}

const NAME_HINTS = [
  'apikey',
  'secret',
  'token',
  'auth',
  'authorization',
  'password',
  'passwd',
  'pwd',
  'clientsecret',
  'accesstoken',
  'refreshtoken',
  'sessiontoken',
  'privatekey',
];

function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[^a-z0-9]/g, '');
}

/** True when a variable/header/parameter name reads as credential-like. */
export function keyLooksSecret(key: string): boolean {
  const normalized = normalizeKey(key);
  return NAME_HINTS.some((hint) => normalized.includes(hint));
}
