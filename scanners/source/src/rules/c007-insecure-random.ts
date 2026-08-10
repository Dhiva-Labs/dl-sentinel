import type { RuleModule, RuleHit } from './types.js';
import { contextWindow, findCallSites, hasContextWord } from '../text.js';
import type { FileContext } from '../context.js';

/**
 * C007 -- insecure randomness for secrets.
 *
 * `Math.random()` (JS) and the `random` module (Python) are not
 * cryptographically secure PRNGs. Using them is completely normal for UI
 * jitter, sampling, shuffling, and the like, so -- same shape as C006 --
 * this only fires when the call appears near (same line, or within two
 * lines either side, including comments) a mention of one of: token,
 * secret, password, otp, session, key, nonce.
 */

const CONTEXT_WORDS = ['token', 'secret', 'password', 'otp', 'session', 'key', 'nonce'];
const CONTEXT_BEFORE = 2;
const CONTEXT_AFTER = 2;

function hasSecretContext(ctx: FileContext, line: number): boolean {
  const window = contextWindow(ctx.lines, line, CONTEXT_BEFORE, CONTEXT_AFTER);
  return hasContextWord(window, CONTEXT_WORDS);
}

function checkJs(ctx: FileContext): RuleHit[] {
  const hits: RuleHit[] = [];
  for (let i = 0; i < ctx.lines.length; i++) {
    if (ctx.commentMask[i]) continue;
    const line = ctx.lines[i] ?? '';
    const lineStart = ctx.lineStarts[i] ?? 0;
    for (const site of findCallSites(line, ['Math.random'], ctx.text, lineStart)) {
      if (hasSecretContext(ctx, i)) hits.push({ line: i, column: site.index });
    }
  }
  return hits;
}

function checkPython(ctx: FileContext): RuleHit[] {
  const hits: RuleHit[] = [];
  const re = /\brandom\.\w+\s*\(/g;
  for (let i = 0; i < ctx.lines.length; i++) {
    if (ctx.commentMask[i]) continue;
    const line = ctx.lines[i] ?? '';
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(line))) {
      if (hasSecretContext(ctx, i)) hits.push({ line: i, column: m.index });
    }
  }
  return hits;
}

export const c007InsecureRandom: RuleModule = {
  meta: {
    id: 'C007',
    title: 'Insecure randomness used for a secret value',
    severity: 'medium',
    defaultConfidence: 'medium',
    category: 'source',
    description:
      "A non-cryptographic random number generator (JavaScript Math.random, Python's " +
      'random module) is used near code that mentions a token, secret, password, OTP, ' +
      'session, key, or nonce. These generators are predictable and not suitable for ' +
      'security-sensitive values.',
    recommendation:
      'Use a cryptographically secure source: crypto.randomBytes/crypto.randomUUID in ' +
      "Node.js, or Python's secrets module (secrets.token_hex, secrets.token_urlsafe).",
    references: [],
  },
  languages: ['js', 'py'],
  check(ctx) {
    switch (ctx.lang) {
      case 'js':
        return checkJs(ctx);
      case 'py':
        return checkPython(ctx);
      default:
        return [];
    }
  },
};
