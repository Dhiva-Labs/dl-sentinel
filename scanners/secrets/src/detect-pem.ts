/**
 * PEM private key detection (S017).
 *
 * The security-relevant property of this rule is that key material never
 * reaches a Finding. Evidence is the BEGIN marker line and nothing else:
 *
 * - multi-line block — the finding points at the BEGIN line, `endLine` at the
 *   END line, and the body lines are never read into any string;
 * - single-line block — a key embedded in JSON/YAML with escaped newlines has
 *   its whole remainder replaced by [REDACTED], and the leading context is
 *   clipped to the characters immediately before the marker.
 */

import { RULE_IDS } from './rules.js';
import type { Detection, FileInput } from './types.js';

const PEM_BEGIN = /-----BEGIN (?:(RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED) )?PRIVATE KEY( BLOCK)?-----/g;
const PEM_END = /-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY( BLOCK)?-----/;

/** How far ahead to look for the END marker before giving up on the block. */
const MAX_BLOCK_LINES = 500;

/** Characters of leading context kept before the BEGIN marker in evidence. */
const LEADING_CONTEXT = 48;

function leadingContext(before: string): string {
  if (before.length <= LEADING_CONTEXT) return before;
  return `…${before.slice(before.length - LEADING_CONTEXT)}`;
}

export interface PemScan {
  detections: Detection[];
  /** 1-based line numbers of block body lines, excluded from heuristic rules. */
  bodyLines: Set<number>;
}

export function detectPrivateKeys(lines: readonly string[]): PemScan {
  const detections: Detection[] = [];
  const bodyLines = new Set<number>();

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    if (line === undefined || !line.includes('-----BEGIN')) continue;

    for (const match of line.matchAll(PEM_BEGIN)) {
      if (match.index === undefined) continue;
      const marker = match[0];
      const before = line.slice(0, match.index);
      const rest = line.slice(match.index + marker.length);
      const inlineBody = rest.trim();
      const hasInlineBody = inlineBody !== '';

      // Find the END marker: on this line, or on a following one.
      let endLine: number | undefined;
      if (PEM_END.test(rest)) {
        endLine = index + 1;
      } else {
        const limit = Math.min(lines.length, index + 1 + MAX_BLOCK_LINES);
        for (let ahead = index + 1; ahead < limit; ahead += 1) {
          const aheadLine = lines[ahead];
          if (aheadLine === undefined) continue;
          if (PEM_END.test(aheadLine)) {
            endLine = ahead + 1;
            break;
          }
          bodyLines.add(ahead + 1);
        }
        if (endLine === undefined) {
          // Unterminated block: keep the body-line exclusions but do not claim
          // an end position.
          for (let ahead = index + 1; ahead < limit; ahead += 1) bodyLines.delete(ahead + 1);
        }
      }

      const evidenceSource = `${leadingContext(before)}${marker}${hasInlineBody ? ' [REDACTED]' : ''}`;

      detections.push({
        ruleId: RULE_IDS.privateKey,
        tier: 'structured',
        // The body is passed as a secret so that any other evidence built from
        // this line has it stripped too; the evidence above never contains it.
        secrets: hasInlineBody ? [inlineBody] : [],
        line: index + 1,
        column: match.index + 1,
        ...(endLine === undefined ? {} : { endLine }),
        evidenceSource,
        // Claim the whole remainder of the line so name/entropy rules do not
        // re-report the same key material.
        span: { start: match.index, end: line.length },
        metadata: {
          keyType: match[1] ?? 'PKCS8',
          terminated: endLine !== undefined,
          inline: hasInlineBody,
        },
      });
    }
  }

  return { detections, bodyLines };
}
