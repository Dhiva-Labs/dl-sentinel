/**
 * Structured-format detectors: vendor token shapes and credential-bearing URLs.
 *
 * Each entry is a table row rather than bespoke code so the set stays auditable
 * — pattern, required context, extra acceptance checks, and the rule it emits
 * are all visible in one place.
 *
 * Every pattern is anchored with explicit boundary lookarounds instead of `\b`,
 * because `\b` does the wrong thing next to `_` and `-`, which appear in most
 * token formats. Patterns are linear (no nested quantifiers) so they cannot
 * backtrack catastrophically on hostile input.
 */

import { shannonEntropy } from '@dl-sentinel/core';
import type { Confidence, Severity } from '@dl-sentinel/core';
import { isNoisyLine } from './file-kinds.js';
import { contextWindow } from './lines.js';
import { RULE_IDS } from './rules.js';
import type { Detection, FileInput } from './types.js';

interface PatternRule {
  ruleId: string;
  /** Global regexes; the secret is capture group `secretGroup` (default 1). */
  patterns: readonly RegExp[];
  secretGroup?: number;
  /** Every regex must match the context window. */
  contextAll?: readonly RegExp[];
  /** At least one regex must match the context window. */
  contextAny?: readonly RegExp[];
  /** Lines above/below included in the context window. Default 2. */
  contextRadius?: number;
  /** Skip lockfiles, minified bundles, and integrity lines. */
  skipNoisy?: boolean;
  /** Extra acceptance test on the captured value. */
  accept?: (value: string, match: RegExpMatchArray) => boolean;
  severity?: Severity;
  confidence?: Confidence;
  metadata?: (value: string, match: RegExpMatchArray) => Record<string, string | number | boolean>;
}

const AWS_CONTEXT = [/aws/i, /amazon/i, /secret[_\s-]?(access[_\s-]?)?key/i];

/** 40 lowercase hex characters is a git object id, not an AWS secret. */
const isHex40 = (value: string): boolean => /^[0-9a-f]{40}$/i.test(value);

const PATTERN_RULES: readonly PatternRule[] = [
  {
    ruleId: RULE_IDS.awsAccessKeyId,
    patterns: [/(?<![A-Za-z0-9])(AKIA[0-9A-Z]{16})(?![A-Za-z0-9])/g],
  },
  {
    ruleId: RULE_IDS.awsSecretAccessKey,
    // AWS secret access keys are exactly 40 characters of the base64 alphabet
    // without padding. Without the context requirement this would match any
    // 40-character blob, so the line (or a neighbour) must name AWS.
    patterns: [/(?<![A-Za-z0-9/+])([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])/g],
    contextAny: AWS_CONTEXT,
    skipNoisy: true,
    accept: (value) => !isHex40(value) && /[A-Za-z]/.test(value) && shannonEntropy(value) >= 3.5,
  },
  {
    ruleId: RULE_IDS.githubToken,
    patterns: [
      /(?<![A-Za-z0-9_])(gh[pousr]_[A-Za-z0-9]{36,})(?![A-Za-z0-9])/g,
      /(?<![A-Za-z0-9_])(github_pat_[A-Za-z0-9_]{22,})(?![A-Za-z0-9_])/g,
    ],
    metadata: (value) => ({
      tokenForm: value.startsWith('github_pat_') ? 'fine-grained' : 'classic',
    }),
  },
  {
    ruleId: RULE_IDS.gitlabToken,
    patterns: [/(?<![A-Za-z0-9_-])(glpat-[0-9A-Za-z_-]{20,})(?![A-Za-z0-9_-])/g],
  },
  {
    ruleId: RULE_IDS.slackToken,
    patterns: [/(?<![A-Za-z0-9-])(xox[baprs]-[A-Za-z0-9-]{10,})(?![A-Za-z0-9-])/g],
  },
  {
    ruleId: RULE_IDS.slackWebhook,
    // The host and /services/ prefix are not secret; the path after it is.
    patterns: [/https:\/\/hooks\.slack\.com\/services\/([A-Za-z0-9_/+-]{12,})/g],
  },
  {
    ruleId: RULE_IDS.stripeLiveKey,
    patterns: [/(?<![A-Za-z0-9_])((?:sk|rk)_live_[A-Za-z0-9]{10,})(?![A-Za-z0-9])/g],
  },
  {
    ruleId: RULE_IDS.stripeTestKey,
    patterns: [/(?<![A-Za-z0-9_])((?:sk|rk)_test_[A-Za-z0-9]{10,})(?![A-Za-z0-9])/g],
  },
  {
    ruleId: RULE_IDS.googleApiKey,
    patterns: [/(?<![A-Za-z0-9_-])(AIza[0-9A-Za-z_-]{35})(?![A-Za-z0-9_-])/g],
  },
  {
    ruleId: RULE_IDS.twilioApiKey,
    patterns: [/(?<![A-Za-z0-9])(SK[0-9a-f]{32})(?![A-Za-z0-9])/g],
  },
  {
    ruleId: RULE_IDS.twilioAccount,
    // An account SID alone is an identifier; it is credential material once an
    // auth token sits beside it, so both words must appear in the context.
    patterns: [
      /(?<![A-Za-z0-9])(AC[0-9a-f]{32})(?![A-Za-z0-9])/g,
      /(?<![A-Za-z0-9])([0-9a-f]{32})(?![A-Za-z0-9])/g,
    ],
    contextAll: [/twilio/i, /auth[_\s-]?token/i],
    skipNoisy: true,
    metadata: (value) => ({
      credentialForm: /^AC[0-9a-f]{32}$/.test(value) ? 'account-sid' : 'auth-token',
    }),
  },
  {
    ruleId: RULE_IDS.sendgridKey,
    patterns: [/(?<![A-Za-z0-9_.-])(SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})(?![A-Za-z0-9_-])/g],
  },
  {
    ruleId: RULE_IDS.npmToken,
    // npm issues 36 characters after the prefix; the bound is open-ended so a
    // longer synthetic value still matches.
    patterns: [/(?<![A-Za-z0-9_])(npm_[A-Za-z0-9]{36,})(?![A-Za-z0-9])/g],
  },
  {
    ruleId: RULE_IDS.openaiKey,
    // sk- with a hyphen, which never collides with Stripe's sk_live_/sk_test_.
    // The character-profile check keeps kebab-case identifiers such as
    // "sk-spinner-fading-circle" out of the results.
    patterns: [/(?<![A-Za-z0-9_-])(sk-[A-Za-z0-9_-]{20,})(?![A-Za-z0-9_-])/g],
    accept: (value) => {
      const body = value.slice(3);
      return /[0-9]/.test(body) && /[A-Z]/.test(body) && shannonEntropy(body) >= 3.5;
    },
  },
  {
    ruleId: RULE_IDS.azureStorageKey,
    patterns: [/AccountKey=([A-Za-z0-9+/=]{30,})/gi],
  },
  {
    ruleId: RULE_IDS.azureSasToken,
    patterns: [/[?&]sig=([A-Za-z0-9%+/=_-]{20,})/gi],
    contextAny: [/\bsv=\d{4}-\d{2}-\d{2}/i, /\.core\.windows\.net/i],
    contextRadius: 0,
  },
  {
    ruleId: RULE_IDS.databaseUrlPassword,
    patterns: [
      /(?<![A-Za-z0-9+.-])(postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?):\/\/([^\s:@/"'`<>]{0,64}):([^\s@/"'`<>]{1,256})@/g,
    ],
    secretGroup: 3,
    metadata: (_value, match) => ({ scheme: match[1] ?? 'unknown' }),
  },
  {
    ruleId: RULE_IDS.basicAuthUrl,
    patterns: [/(?<![A-Za-z0-9+.-])(https?):\/\/([^\s:@/"'`<>]{1,64}):([^\s@/"'`<>]{1,256})@/g],
    secretGroup: 3,
    metadata: (_value, match) => ({ scheme: match[1] ?? 'unknown' }),
  },
  {
    ruleId: RULE_IDS.jsonWebToken,
    patterns: [
      /(?<![A-Za-z0-9_-])(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})(?![A-Za-z0-9_-])/g,
    ],
  },
];

function contextMatches(rule: PatternRule, file: FileInput, lineIndex: number): boolean {
  if (rule.contextAll === undefined && rule.contextAny === undefined) return true;
  const window = contextWindow(file.lines, lineIndex, rule.contextRadius ?? 2);
  if (rule.contextAll !== undefined && !rule.contextAll.every((re) => re.test(window))) {
    return false;
  }
  if (rule.contextAny !== undefined && !rule.contextAny.some((re) => re.test(window))) {
    return false;
  }
  return true;
}

function detectionsForLine(
  rule: PatternRule,
  file: FileInput,
  line: string,
  lineIndex: number,
): Detection[] {
  const out: Detection[] = [];
  const secretGroup = rule.secretGroup ?? 1;
  for (const pattern of rule.patterns) {
    for (const match of line.matchAll(pattern)) {
      const value = match[secretGroup];
      if (value === undefined || match.index === undefined) continue;
      if (rule.accept !== undefined && !rule.accept(value, match)) continue;
      // The captured value is always a substring of the whole match; take the
      // last occurrence so `user:user@host` resolves to the password.
      const offsetInMatch = match[0].lastIndexOf(value);
      const start = match.index + (offsetInMatch === -1 ? 0 : offsetInMatch);
      out.push({
        ruleId: rule.ruleId,
        tier: 'structured',
        secrets: [value],
        allowlistValue: value,
        line: lineIndex + 1,
        column: start + 1,
        evidenceSource: line,
        span: { start, end: start + value.length },
        ...(rule.severity === undefined ? {} : { severity: rule.severity }),
        ...(rule.confidence === undefined ? {} : { confidence: rule.confidence }),
        ...(rule.metadata === undefined ? {} : { metadata: rule.metadata(value, match) }),
      });
    }
  }
  return out;
}

/** Run every structured-format rule over one file. */
export function detectPatterns(file: FileInput): Detection[] {
  const out: Detection[] = [];
  for (const rule of PATTERN_RULES) {
    for (let index = 0; index < file.lines.length; index += 1) {
      const line = file.lines[index];
      if (line === undefined || line === '') continue;
      if (rule.skipNoisy === true && (file.isNoisy || isNoisyLine(line))) continue;
      if (!contextMatches(rule, file, index)) continue;
      out.push(...detectionsForLine(rule, file, line, index));
    }
  }
  return out;
}
