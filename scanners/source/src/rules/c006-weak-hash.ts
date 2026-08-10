import type { RuleModule, RuleHit } from './types.js';
import { contextWindow, findCallSites, hasContextWord } from '../text.js';
import type { FileContext } from '../context.js';

/**
 * C006 -- weak hashing for credentials.
 *
 * MD5/SHA-1 are fast, general-purpose digests: entirely reasonable for file
 * checksums, cache keys, or ETags, and a rule that flagged every use of them
 * would be exactly the "floods meaningless findings" failure mode the
 * mission warns about. So this stays a single rule with a context
 * requirement: the hashing call must appear near (same line, or within two
 * lines either side, including comments) a mention of password, passwd,
 * pwd, or credential. A checksum/ETag use of MD5 with no such word nearby
 * does not match.
 *
 * Covers: JS `crypto.createHash('md5'|'sha1')`, Python `hashlib.md5`/
 * `hashlib.sha1`, Ruby `Digest::MD5`/`Digest::SHA1`, PHP `md5()`/`sha1()`,
 * and Java `MessageDigest.getInstance("MD5"|"SHA1"|"SHA-1")`.
 */

const CONTEXT_WORDS = ['password', 'passwd', 'pwd', 'credential'];
const CONTEXT_BEFORE = 2;
const CONTEXT_AFTER = 2;

function hasPasswordContext(ctx: FileContext, line: number): boolean {
  const window = contextWindow(ctx.lines, line, CONTEXT_BEFORE, CONTEXT_AFTER);
  return hasContextWord(window, CONTEXT_WORDS);
}

function checkJs(ctx: FileContext): RuleHit[] {
  const hits: RuleHit[] = [];
  for (let i = 0; i < ctx.lines.length; i++) {
    if (ctx.commentMask[i]) continue;
    const line = ctx.lines[i] ?? '';
    const lineStart = ctx.lineStarts[i] ?? 0;
    for (const site of findCallSites(line, ['createHash'], ctx.text, lineStart)) {
      if (!/^\s*['"](?:md5|sha1)['"]\s*$/i.test(site.args)) continue;
      if (hasPasswordContext(ctx, i)) hits.push({ line: i, column: site.index });
    }
  }
  return hits;
}

function checkPython(ctx: FileContext): RuleHit[] {
  const hits: RuleHit[] = [];
  for (let i = 0; i < ctx.lines.length; i++) {
    if (ctx.commentMask[i]) continue;
    const line = ctx.lines[i] ?? '';
    const lineStart = ctx.lineStarts[i] ?? 0;
    for (const site of findCallSites(line, ['hashlib.md5', 'hashlib.sha1'], ctx.text, lineStart)) {
      if (hasPasswordContext(ctx, i)) hits.push({ line: i, column: site.index });
    }
  }
  return hits;
}

function checkRuby(ctx: FileContext): RuleHit[] {
  const hits: RuleHit[] = [];
  const re = /Digest::(?:MD5|SHA1)/g;
  for (let i = 0; i < ctx.lines.length; i++) {
    if (ctx.commentMask[i]) continue;
    const line = ctx.lines[i] ?? '';
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(line))) {
      if (hasPasswordContext(ctx, i)) hits.push({ line: i, column: m.index });
    }
  }
  return hits;
}

function checkPhp(ctx: FileContext): RuleHit[] {
  const hits: RuleHit[] = [];
  for (let i = 0; i < ctx.lines.length; i++) {
    if (ctx.commentMask[i]) continue;
    const line = ctx.lines[i] ?? '';
    const lineStart = ctx.lineStarts[i] ?? 0;
    for (const site of findCallSites(line, ['md5', 'sha1'], ctx.text, lineStart)) {
      if (hasPasswordContext(ctx, i)) hits.push({ line: i, column: site.index });
    }
  }
  return hits;
}

function checkJava(ctx: FileContext): RuleHit[] {
  const hits: RuleHit[] = [];
  for (let i = 0; i < ctx.lines.length; i++) {
    if (ctx.commentMask[i]) continue;
    const line = ctx.lines[i] ?? '';
    const lineStart = ctx.lineStarts[i] ?? 0;
    for (const site of findCallSites(line, ['MessageDigest.getInstance'], ctx.text, lineStart)) {
      if (!/md5|sha-?1/i.test(site.args)) continue;
      if (hasPasswordContext(ctx, i)) hits.push({ line: i, column: site.index });
    }
  }
  return hits;
}

export const c006WeakHash: RuleModule = {
  meta: {
    id: 'C006',
    title: 'Weak hash algorithm used for credentials',
    severity: 'high',
    defaultConfidence: 'medium',
    category: 'source',
    description:
      'MD5 or SHA-1 is used to hash a value in a context that mentions passwords or ' +
      'credentials. Both are fast, general-purpose digests designed for speed, which ' +
      'makes brute-forcing and rainbow-table attacks practical against stored ' +
      'password hashes.',
    recommendation:
      'Use a password-hashing KDF designed to be slow: bcrypt, scrypt, Argon2, or ' +
      'PBKDF2 with a high iteration count and a per-password salt.',
    references: [],
  },
  languages: ['js', 'py', 'rb', 'php', 'java'],
  check(ctx) {
    switch (ctx.lang) {
      case 'js':
        return checkJs(ctx);
      case 'py':
        return checkPython(ctx);
      case 'rb':
        return checkRuby(ctx);
      case 'php':
        return checkPhp(ctx);
      case 'java':
        return checkJava(ctx);
      default:
        return [];
    }
  },
};
