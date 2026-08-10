import type { Finding } from '@dl-sentinel/core';
import { buildFinding } from '../build-finding.js';
import { MAX_WALK_DEPTH } from '../util.js';

function looksLikeRateLimitKey(key: string): boolean {
  const normalized = key.toLowerCase().replace(/[^a-z]/g, '');
  return normalized.includes('ratelimit');
}

/**
 * Generic, format-agnostic scan of the whole parsed document for any signal
 * that rate limiting was considered: a '429' response-status key (OpenAPI 3 /
 * Swagger 2 responses maps), a literal 429 status code value (Postman saved
 * example responses use `{ "code": 429 }`), or a header name containing
 * "rate limit" (X-RateLimit-*, RateLimit-*, etc.) anywhere in the tree.
 * Cycle-safe (object identity) and depth-capped, since this walks the raw
 * parsed document rather than a schema tree.
 */
function scanForRateLimitSignal(node: unknown, seen: Set<object>, depth: number): boolean {
  if (depth > MAX_WALK_DEPTH) return false;
  if (Array.isArray(node)) {
    if (seen.has(node)) return false;
    seen.add(node);
    return node.some((child) => scanForRateLimitSignal(child, seen, depth + 1));
  }
  if (typeof node === 'object' && node !== null) {
    if (seen.has(node)) return false;
    seen.add(node);
    for (const [key, value] of Object.entries(node)) {
      if (key === '429') return true;
      if (value === 429) return true;
      if (looksLikeRateLimitKey(key)) return true;
      if (scanForRateLimitSignal(value, seen, depth + 1)) return true;
    }
    return false;
  }
  return false;
}

/** A007 — no 429 response and no rate-limit header signal anywhere in the document (one finding per document). */
export function runMissingRateLimitSignal(root: Record<string, unknown>, file: string): Finding[] {
  const found = scanForRateLimitSignal(root, new Set(), 0);
  if (found) return [];
  return [
    buildFinding({
      ruleId: 'A007',
      title: 'No rate-limit signal in the API definition',
      description:
        'The document defines no 429 (Too Many Requests) response and no rate-limit related header (X-RateLimit-*, RateLimit-*) anywhere, suggesting rate limiting was not documented for this API.',
      severity: 'low',
      confidence: 'high',
      qualifier: 'potential',
      file,
      evidence: 'no "429" response and no rate-limit header found anywhere in the document',
      recommendation:
        'Document rate-limit behavior: add 429 responses where relevant and/or advertise limits via RateLimit/X-RateLimit-* headers.',
    }),
  ];
}
