/**
 * Shared "does this look like a hardcoded secret" heuristic used by every
 * name+value rule: Dockerfile ENV/ARG (I004), compose environment (I014),
 * and Kubernetes container env (I028).
 *
 * The heuristic is intentionally simple and documented: a variable name
 * matching a small set of secret-shaped keywords, holding a literal value
 * that isn't an obvious placeholder or a reference to another variable.
 * It will over-match compound names (e.g. `TOKENIZER_MODE`) — that is a
 * deliberate precision/recall tradeoff spelled out by the rule spec, not an
 * oversight.
 */

/** Case-insensitive; matched as a substring of the variable/key name. */
const SECRET_NAME_PATTERN = /(PASSWORD|SECRET|TOKEN|API_?KEY|CREDENTIAL)/i;

export function looksLikeSecretName(name: string): boolean {
  return SECRET_NAME_PATTERN.test(name);
}

/**
 * Whole-value placeholder tokens: obvious "fill this in" markers that are
 * not literal secrets even though they sit in a secret-shaped variable.
 * Matched against the *entire* trimmed value (not a substring) so that a
 * real, if weak, secret containing one of these words as part of a longer
 * value (e.g. a planted `EXAMPLE`-marked test fixture secret) is not
 * accidentally excluded.
 */
const WHOLE_VALUE_PLACEHOLDER =
  /^(change[-_ ]?(me|it)|placeholder|replace[-_ ]?me|your[-_ ]?.*|xxx+|todo|tbd|n\/?a|none|null|redacted|\[redacted\]|\*+|-+|_+|\.+)$/i;

/** Wrapping styles that mark a value as a template slot rather than a literal. */
const WRAPPED_PLACEHOLDER = /^<[^>]*>$|^\{\{.*\}\}$|^%[^%]*%$/;

/** `${VAR}` / `${VAR:-default}` style shell or build-arg interpolation. */
const SHELL_INTERPOLATION = /^\$\{[^}]*\}$/;

/** Bare `$VAR` reference. */
const SHELL_VAR_REFERENCE = /^\$[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * True when `value` is empty, a variable reference, or an obvious
 * placeholder rather than a literal secret value.
 */
export function isPlaceholderValue(value: string): boolean {
  const trimmed = value.trim();
  if (trimmed.length === 0) return true;
  if (SHELL_INTERPOLATION.test(trimmed)) return true;
  if (SHELL_VAR_REFERENCE.test(trimmed)) return true;
  if (WRAPPED_PLACEHOLDER.test(trimmed)) return true;
  if (WHOLE_VALUE_PLACEHOLDER.test(trimmed)) return true;
  return false;
}

/**
 * True when `name` looks like a secret-holding variable AND `value` is a
 * literal, non-placeholder value worth flagging and redacting.
 */
export function isLiteralSecretValue(name: string, value: string | undefined): boolean {
  if (value === undefined) return false;
  if (!looksLikeSecretName(name)) return false;
  return !isPlaceholderValue(value);
}
