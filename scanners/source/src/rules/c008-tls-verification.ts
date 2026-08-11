import type { RuleModule, RuleHit } from './types.js';
import type { FileContext } from '../context.js';
import type { Lang } from '../language.js';

/**
 * C008 -- TLS certificate verification disabled.
 *
 * Every pattern here is an unambiguous, single-line, always-on-when-present
 * signal (unlike C006/C007 there is no legitimate reason to write any of
 * these in application code), so no dynamism or context check is needed --
 * confidence is high per the mission's rule table.
 *
 * - JS: `rejectUnauthorized: false` (https/tls options object), or setting
 *   `NODE_TLS_REJECT_UNAUTHORIZED` to `'0'`.
 * - Python: `requests`'s `verify=False`, or disabling the stdlib `ssl`
 *   module's checks directly (`verify_mode = ssl.CERT_NONE`,
 *   `check_hostname = False`) -- the latter two are not in the mission's
 *   example list verbatim but are the same class of unambiguous signal and
 *   are what this scanner's own read-only fixture (unsafe.py) actually
 *   plants, so they are included deliberately.
 * - Go: `InsecureSkipVerify: true` in a tls.Config literal.
 * - PHP: `curl_setopt(..., CURLOPT_SSL_VERIFYPEER, false)` (or `0`).
 */

interface Pattern {
  regex: RegExp;
}

const PATTERNS_BY_LANG: Partial<Record<Lang, Pattern[]>> = {
  js: [
    { regex: /rejectUnauthorized\s*:\s*false\b/gi },
    { regex: /NODE_TLS_REJECT_UNAUTHORIZED['"]?\s*[=:]\s*['"]?0['"]?/g },
  ],
  py: [
    { regex: /\bverify\s*=\s*False\b/g },
    { regex: /verify_mode\s*=\s*ssl\.CERT_NONE\b/g },
    { regex: /check_hostname\s*=\s*False\b/g },
  ],
  go: [{ regex: /InsecureSkipVerify\s*:\s*true\b/gi }],
  php: [{ regex: /CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)\b/gi }],
};

function checkLines(ctx: FileContext, patterns: Pattern[]): RuleHit[] {
  const hits: RuleHit[] = [];
  for (let i = 0; i < ctx.lines.length; i++) {
    if (ctx.commentMask[i]) continue;
    const line = ctx.lines[i] ?? '';
    for (const { regex } of patterns) {
      regex.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = regex.exec(line))) {
        hits.push({ line: i, column: m.index });
      }
    }
  }
  return hits;
}

export const c008TlsVerification: RuleModule = {
  meta: {
    id: 'C008',
    title: 'TLS certificate verification disabled',
    severity: 'high',
    defaultConfidence: 'high',
    category: 'source',
    description:
      'TLS/SSL certificate verification is explicitly disabled (rejectUnauthorized: ' +
      'false, NODE_TLS_REJECT_UNAUTHORIZED=0, requests verify=False, disabling the ' +
      "Python ssl module's hostname/certificate checks, Go InsecureSkipVerify: true, " +
      'or curl CURLOPT_SSL_VERIFYPEER false/0). This allows man-in-the-middle attacks ' +
      'against the connection.',
    recommendation:
      'Remove the override and let certificate verification run normally. If a ' +
      'private CA is involved, add its certificate to the trust store instead of ' +
      'disabling verification.',
    references: [],
    compliance: { cwe: ['CWE-295'], owasp: ['A07:2021'] },
  },
  languages: ['js', 'py', 'go', 'php'],
  check(ctx) {
    const patterns = PATTERNS_BY_LANG[ctx.lang];
    if (!patterns) return [];
    return checkLines(ctx, patterns);
  },
};
