/**
 * Redaction utilities. Secret values must never appear in findings, reports,
 * logs, or terminal output — every scanner that handles secret-like values is
 * required to pass evidence through these helpers.
 */

export const REDACTED = '[REDACTED]';

/**
 * Secrets shorter than this are not searched for inside evidence text:
 * replacing ubiquitous 2-3 char substrings would destroy the evidence line
 * while offering no real protection.
 */
const MIN_REDACTABLE_LENGTH = 4;

/** Always returns the redaction marker. Exists to make intent explicit. */
export function redactValue(_value: string): string {
  return REDACTED;
}

/**
 * Produce a safe evidence string from a line of source text: every occurrence
 * of every provided secret value is replaced with [REDACTED], and the result
 * is trimmed and truncated.
 */
export function redactEvidence(text: string, secrets: readonly string[], maxLength = 200): string {
  let out = text;
  // Longest first so substrings of longer secrets cannot leave residue.
  const ordered = [...secrets]
    .filter((s) => s.length >= MIN_REDACTABLE_LENGTH)
    .sort((a, b) => b.length - a.length);
  for (const secret of ordered) {
    out = out.split(secret).join(REDACTED);
  }
  out = out.trim();
  if (out.length > maxLength) {
    out = `${out.slice(0, maxLength)}…`;
  }
  return out;
}

/** True if the (unredacted) value still appears in the given text. */
export function containsSecret(text: string, secret: string): boolean {
  return secret.length >= MIN_REDACTABLE_LENGTH && text.includes(secret);
}
