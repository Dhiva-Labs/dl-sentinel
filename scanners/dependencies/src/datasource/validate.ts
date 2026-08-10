import type { Advisory, AdvisorySeverity, AffectedRange, Ecosystem } from '../types.js';

const VALID_ECOSYSTEMS: readonly Ecosystem[] = ['npm', 'pip', 'go', 'cargo'];
const VALID_SEVERITIES: readonly AdvisorySeverity[] = ['critical', 'high', 'medium', 'low'];

function typeOf(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  return typeof value;
}

function requireString(obj: Record<string, unknown>, field: string, where: string): string {
  const value = obj[field];
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${where}.${field} must be a non-empty string, got ${typeOf(value)}`);
  }
  return value;
}

function validateRange(entry: unknown, where: string): AffectedRange {
  if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
    throw new Error(`${where} must be an object, got ${typeOf(entry)}`);
  }
  const obj = entry as Record<string, unknown>;
  const introduced = obj.introduced;
  const fixed = obj.fixed;
  if (introduced !== undefined && typeof introduced !== 'string') {
    throw new Error(`${where}.introduced must be a string when present`);
  }
  if (fixed !== undefined && typeof fixed !== 'string') {
    throw new Error(`${where}.fixed must be a string when present`);
  }
  if (introduced === undefined && fixed === undefined) {
    throw new Error(`${where} must have at least one of "introduced" or "fixed"`);
  }
  return {
    introduced: introduced as string | undefined,
    fixed: fixed as string | undefined,
  };
}

function validateAdvisory(entry: unknown, index: number, sourceLabel: string): Advisory {
  const where = `${sourceLabel}[${index}]`;
  if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
    throw new Error(`${where} must be an object, got ${typeOf(entry)}`);
  }
  const obj = entry as Record<string, unknown>;

  const id = requireString(obj, 'id', where);
  const ecosystem = requireString(obj, 'ecosystem', where);
  if (!VALID_ECOSYSTEMS.includes(ecosystem as Ecosystem)) {
    throw new Error(
      `${where}.ecosystem must be one of ${VALID_ECOSYSTEMS.join(', ')}, got "${ecosystem}"`,
    );
  }
  const name = requireString(obj, 'name', where);
  const severity = requireString(obj, 'severity', where);
  if (!VALID_SEVERITIES.includes(severity as AdvisorySeverity)) {
    throw new Error(
      `${where}.severity must be one of ${VALID_SEVERITIES.join(', ')}, got "${severity}"`,
    );
  }
  const summary = requireString(obj, 'summary', where);

  const rawRanges = obj.affectedRanges;
  if (!Array.isArray(rawRanges) || rawRanges.length === 0) {
    throw new Error(`${where}.affectedRanges must be a non-empty array`);
  }
  const affectedRanges = rawRanges.map((range, i) =>
    validateRange(range, `${where}.affectedRanges[${i}]`),
  );

  const references = obj.references;
  if (!Array.isArray(references) || references.some((r) => typeof r !== 'string')) {
    throw new Error(`${where}.references must be an array of strings`);
  }

  return {
    id,
    ecosystem: ecosystem as Ecosystem,
    name,
    severity: severity as AdvisorySeverity,
    summary,
    affectedRanges,
    references: references as string[],
  };
}

/**
 * Validate that `data` is a well-formed advisory database: a JSON array of
 * objects matching the `Advisory` shape. Throws a descriptive `Error` on the
 * first problem found — callers (FileDataSource) let this propagate so a
 * misconfigured database surfaces as a clear scanner error rather than
 * silently reporting nothing, or worse, guessing at malformed data.
 */
export function validateAdvisoryDb(data: unknown, sourceLabel: string): Advisory[] {
  if (!Array.isArray(data)) {
    throw new Error(`Advisory database ${sourceLabel} must be a JSON array, got ${typeOf(data)}`);
  }
  return data.map((entry, index) => validateAdvisory(entry, index, sourceLabel));
}
