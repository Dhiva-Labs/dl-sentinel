/**
 * Name-based detectors (heuristic tier).
 *
 * - S021 — a credential-named setting assigned a literal in an environment or
 *   configuration file.
 * - S022 — a credential-named identifier assigned a quoted, high-entropy
 *   literal anywhere.
 *
 * Both consult `isPlaceholder()`, so documentation values (`YOUR_API_KEY`,
 * `${DB_PASSWORD}`, `process.env.TOKEN`) are not findings. Both are also
 * suppressed by any overlapping structured match, so a token that S001–S020
 * already reported is reported once, by the rule that knows what it is.
 */

import { shannonEntropy } from '@dl-sentinel/core';
import { isNoisyLine } from './file-kinds.js';
import { isSensitiveIdentifier } from './identifiers.js';
import { isPlaceholder } from './placeholders.js';
import { RULE_IDS } from './rules.js';
import type { Detection, FileInput } from './types.js';

/** Shortest literal the `.env` rule will report. */
const MIN_ASSIGNED_VALUE_LENGTH = 6;

/** Shortest literal the entropy rule will consider. */
const MIN_ENTROPY_VALUE_LENGTH = 16;

/** Entropy above which a literal looks generated rather than written. */
const ENTROPY_THRESHOLD = 4.0;

/** Heuristics stop looking at absurdly long lines (generated content). */
const MAX_HEURISTIC_LINE_LENGTH = 4000;

/** `KEY=value`, `KEY: value`, `- KEY=value`, `export KEY=value`, `"key": value`. */
const ASSIGNMENT_LINE =
  /^(?:\s*(?:-\s+)?(?:export\s+)?)(["']?)([A-Za-z_][A-Za-z0-9_.$-]*)\1\s*(?::=|[:=])\s*(.*)$/;

/** `identifier = "literal"` anywhere on a line, for source files. */
const QUOTED_ASSIGNMENT =
  /([A-Za-z_$][A-Za-z0-9_$.-]*)\s*(?::=|=>|[:=])\s*(["'`])([^"'`\n]{16,})\2/g;

const NUMERIC_OR_BOOLEAN = /^(?:[-+]?\d+(?:\.\d+)?|true|false|yes|no|on|off|null|nil|none|~)$/i;
const BARE_URL = /^[a-z][a-z0-9+.-]*:\/\//i;
const FILESYSTEM_PATH = /^(?:\.{0,2}\/|~\/|[A-Za-z]:[\\/])/;
const FILE_NAME = /^[\w.-]+\.(?:pem|key|crt|cer|p12|pfx|jks|json|ya?ml|txt|log|sh|py|js|ts)$/i;

interface ParsedValue {
  value: string;
  /** 0-based offset of the value within the line. */
  start: number;
}

/** Extract the assigned literal from the text following the separator. */
function parseAssignedValue(line: string, rest: string): ParsedValue | undefined {
  const restStart = line.length - rest.length;
  const quote = rest.charAt(0);
  if (quote === '"' || quote === "'" || quote === '`') {
    const close = rest.indexOf(quote, 1);
    if (close > 0) {
      return { value: rest.slice(1, close), start: restStart + 1 };
    }
    return { value: rest.slice(1).trim(), start: restStart + 1 };
  }
  let end = rest.length;
  const comment = rest.search(/\s+(?:#|\/\/)/);
  if (comment >= 0) end = comment;
  const raw = rest.slice(0, end);
  const trimmed = raw.replace(/[\s,;]+$/, '');
  return { value: trimmed, start: restStart };
}

/** Values that are structurally not credentials regardless of their name. */
function isUninterestingValue(value: string): boolean {
  return (
    NUMERIC_OR_BOOLEAN.test(value) ||
    BARE_URL.test(value) ||
    FILESYSTEM_PATH.test(value) ||
    FILE_NAME.test(value) ||
    /\s/.test(value)
  );
}

/** Lines the heuristic rules will look at: present, bounded, not generated. */
function isScannableLine(
  file: FileInput,
  line: string | undefined,
  lineNumber: number,
): line is string {
  if (line === undefined || line === '') return false;
  if (line.length > MAX_HEURISTIC_LINE_LENGTH) return false;
  if (file.pemBodyLines.has(lineNumber)) return false;
  if (isNoisyLine(line)) return false;
  return true;
}

/** S021 — credential-named setting assigned a literal in env/config files. */
export function detectSensitiveAssignments(file: FileInput): Detection[] {
  if (file.isNoisy) return [];
  if (!file.isEnvLike && !file.isConfigLike) return [];

  const out: Detection[] = [];
  for (let index = 0; index < file.lines.length; index += 1) {
    const line = file.lines[index];
    if (!isScannableLine(file, line, index + 1)) continue;

    const match = ASSIGNMENT_LINE.exec(line);
    const key = match?.[2];
    const rest = match?.[3];
    if (key === undefined || rest === undefined) continue;
    if (!isSensitiveIdentifier(key)) continue;

    const parsed = parseAssignedValue(line, rest);
    if (parsed === undefined) continue;
    const { value } = parsed;
    if (value.length < MIN_ASSIGNED_VALUE_LENGTH) continue;
    if (isUninterestingValue(value)) continue;
    if (isPlaceholder(value)) continue;

    out.push({
      ruleId: RULE_IDS.sensitiveAssignment,
      tier: 'heuristic',
      secrets: [value],
      allowlistValue: value,
      line: index + 1,
      column: parsed.start + 1,
      evidenceSource: line,
      span: { start: parsed.start, end: parsed.start + value.length },
      metadata: {
        setting: key,
        fileKind: file.isEnvLike ? 'env' : 'config',
        valueLength: value.length,
      },
    });
  }
  return out;
}

/** S022 — credential-named identifier assigned a high-entropy quoted literal. */
export function detectHighEntropyAssignments(file: FileInput): Detection[] {
  if (file.isNoisy) return [];

  const out: Detection[] = [];
  for (let index = 0; index < file.lines.length; index += 1) {
    const line = file.lines[index];
    if (!isScannableLine(file, line, index + 1)) continue;

    for (const match of line.matchAll(QUOTED_ASSIGNMENT)) {
      const identifier = match[1];
      const value = match[3];
      if (identifier === undefined || value === undefined || match.index === undefined) continue;
      if (!isSensitiveIdentifier(identifier)) continue;
      if (value.length < MIN_ENTROPY_VALUE_LENGTH) continue;
      if (isUninterestingValue(value)) continue;
      if (isPlaceholder(value)) continue;
      const entropy = shannonEntropy(value);
      if (entropy <= ENTROPY_THRESHOLD) continue;

      const offsetInMatch = match[0].lastIndexOf(value);
      const start = match.index + (offsetInMatch === -1 ? 0 : offsetInMatch);
      out.push({
        ruleId: RULE_IDS.highEntropyAssignment,
        tier: 'heuristic',
        secrets: [value],
        allowlistValue: value,
        line: index + 1,
        column: start + 1,
        evidenceSource: line,
        span: { start, end: start + value.length },
        metadata: {
          identifier,
          valueLength: value.length,
          entropy: Number(entropy.toFixed(2)),
        },
      });
    }
  }
  return out;
}
