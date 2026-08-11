import type { RuleModule, RuleHit } from './types.js';
import { contextWindow } from '../text.js';
import type { FileContext } from '../context.js';

/**
 * C009 -- permissive CORS, severity depends on credentials.
 *
 * Detects a wildcard CORS origin either as a raw header value
 * (`Access-Control-Allow-Origin: '*'`, language-agnostic since it is just a
 * header name/value pair) or as an Express `cors({ origin: '*' })` options
 * object. A `cors({...})` options object commonly spans several lines, so
 * once a wildcard-origin line is found, a window of surrounding lines is
 * searched for a `credentials: true` (or `Access-Control-Allow-Credentials:
 * true`) signal.
 *
 * `*` combined with credentials is the seriously misconfigured case
 * (browsers should refuse this combination, but plenty of non-browser HTTP
 * clients will not, and some server frameworks do not enforce it) --
 * medium/medium per the mission's rule table. `*` alone (no credentials
 * anywhere nearby) is a lower-severity finding of the *same* rule, per the
 * mission's "per-finding severity" instruction: still worth flagging, but a
 * wildcard origin with no credentials exposure is a much smaller exposure.
 */

const WILDCARD_ORIGIN_PATTERNS = [
  /\borigin\s*:\s*['"]\*['"]/i,
  /Access-Control-Allow-Origin['"]?\s*[,:]\s*['"]\*['"]/i,
];
const CREDENTIALS_TRUE_PATTERNS = [
  /credentials\s*[:=]\s*(['"]?)true\1/i,
  /Access-Control-Allow-Credentials['"]?\s*[,:]\s*['"]?true['"]?/i,
];
const WINDOW_BEFORE = 6;
const WINDOW_AFTER = 6;

function matchesAny(text: string, patterns: readonly RegExp[]): boolean {
  return patterns.some((p) => p.test(text));
}

export const c009Cors: RuleModule = {
  meta: {
    id: 'C009',
    title: 'Permissive CORS configuration',
    severity: 'medium',
    defaultConfidence: 'medium',
    category: 'source',
    description:
      "The Access-Control-Allow-Origin response is set to '*' (a wildcard, reflecting " +
      'or allowing any origin). When combined with credentials (cookies or ' +
      'Authorization headers) enabled, this can let any website read authenticated ' +
      "responses from users' browsers. A wildcard origin with no credentials nearby " +
      'is a smaller, lower-severity exposure.',
    recommendation:
      'Restrict Access-Control-Allow-Origin to an explicit allowlist of trusted ' +
      'origins, and never combine a wildcard origin with credentialed requests.',
    references: [],
    compliance: { cwe: ['CWE-942'], owasp: ['A05:2021'] },
  },
  languages: ['js', 'py', 'rb', 'php', 'go', 'java'],
  check(ctx: FileContext) {
    const hits: RuleHit[] = [];
    for (let i = 0; i < ctx.lines.length; i++) {
      if (ctx.commentMask[i]) continue;
      const line = ctx.lines[i] ?? '';
      for (const pattern of WILDCARD_ORIGIN_PATTERNS) {
        pattern.lastIndex = 0;
        const m = pattern.exec(line);
        if (!m) continue;
        const window = contextWindow(ctx.lines, i, WINDOW_BEFORE, WINDOW_AFTER);
        const withCredentials = matchesAny(window, CREDENTIALS_TRUE_PATTERNS);
        hits.push({ line: i, column: m.index, severity: withCredentials ? 'medium' : 'low' });
      }
    }
    return hits;
  },
};
