/**
 * The scan pass: read each file, run the detectors, then turn raw detections
 * into Findings.
 *
 * Everything that protects the no-leak invariant lives here:
 *
 * 1. evidence is built with `redactEvidence(line, everySecretFoundOnThatLine)`,
 *    not just the one value the rule matched — otherwise a line holding two
 *    tokens would leak the second one through the first one's evidence — and
 *    it is redacted before it is clipped, never the other way round;
 * 2. a detection whose value is too short for `redactEvidence` to remove
 *    (< 4 characters, core's MIN_REDACTABLE_LENGTH) is dropped rather than
 *    reported with a line it cannot sanitize;
 * 3. every assembled finding is re-checked field by field against the raw
 *    values from its file, and dropped if any survived;
 * 4. nothing else — titles, descriptions, metadata, log lines, and error
 *    messages — is ever built from file content.
 */

import { containsSecret, createFinding, REDACTED, redactEvidence } from '@dl-sentinel/core';
import type { FileRef, Finding, ScanContext, ScanLogger } from '@dl-sentinel/core';
import { readSecretsConfig } from './config.js';
import type { SecretsConfig } from './config.js';
import { detectHighEntropyAssignments, detectSensitiveAssignments } from './detect-assignments.js';
import { detectPatterns } from './detect-patterns.js';
import { detectPrivateKeys } from './detect-pem.js';
import { isConfigLikeFile, isEnvLikeFile, isNoisyFile } from './file-kinds.js';
import { splitLines } from './lines.js';
import { isNonSecretReference } from './placeholders.js';
import { ruleMeta } from './rules.js';
import type { Detection, FileInput, Span } from './types.js';

/** Mirrors MIN_REDACTABLE_LENGTH in packages/core/src/redact.ts. */
const MIN_REDACTABLE_LENGTH = 4;

/** Bound on how much one pathological file can contribute to a report. */
const MAX_FINDINGS_PER_FILE = 200;

/** Evidence length cap (docs/finding-schema.md: "≤ ~200 chars"). */
const EVIDENCE_MAX_LENGTH = 200;

/** Characters of context kept before the redaction marker on a long line. */
const EVIDENCE_LEAD = 60;

export const SCANNER_ID = 'secrets';

export async function scanForSecrets(context: ScanContext): Promise<Finding[]> {
  const config = readSecretsConfig(context.config, context.logger);
  if (!config.enabled) return [];

  const findings: Finding[] = [];
  for (const file of context.files) {
    // Cooperative cancellation: the engine treats any throw after an abort as
    // cancellation rather than scanner failure (docs/scanner-interface.md).
    if (context.signal.aborted) {
      throw new Error('secrets scan aborted');
    }
    if (config.isIgnoredPath(file.relPath)) continue;

    const text = await readFileText(context, file);
    if (text === undefined) continue;
    findings.push(...findingsForFile(file.relPath, text, config, context.logger));
  }

  return sortFindings(findings);
}

/** Read a file, turning an unreadable file into a skip rather than a failure. */
async function readFileText(context: ScanContext, file: FileRef): Promise<string | undefined> {
  try {
    return await context.readFile(file);
  } catch (error) {
    // Deliberately logs no error message: only the path and the error kind,
    // so file content can never reach a log line through an exception.
    context.logger.warn(`secrets: skipping unreadable file ${file.relPath} (${errorKind(error)})`);
    return undefined;
  }
}

function errorKind(error: unknown): string {
  if (typeof error === 'object' && error !== null) {
    const code = (error as { code?: unknown }).code;
    if (typeof code === 'string') return code;
    const name = (error as { name?: unknown }).name;
    if (typeof name === 'string') return name;
  }
  return 'unknown error';
}

function findingsForFile(
  relPath: string,
  text: string,
  config: SecretsConfig,
  logger: ScanLogger,
): Finding[] {
  const lines = splitLines(text);
  const pem = detectPrivateKeys(lines);
  const file: FileInput = {
    relPath,
    lines,
    isEnvLike: isEnvLikeFile(relPath),
    isConfigLike: isConfigLikeFile(relPath),
    isNoisy: isNoisyFile(relPath),
    pemBodyLines: pem.bodyLines,
  };

  const detections = [
    ...pem.detections,
    ...detectPatterns(file),
    ...detectSensitiveAssignments(file),
    ...detectHighEntropyAssignments(file),
  ].filter((detection) => isReportable(detection));

  // Every raw value seen on a line, so one rule's evidence cannot expose
  // another rule's secret. Built before allowlisting and suppression, so
  // suppressed matches still get redacted out of the evidence that remains.
  const secretsByLine = new Map<number, string[]>();
  for (const detection of detections) {
    const bucket = secretsByLine.get(detection.line) ?? [];
    for (const secret of detection.secrets) {
      if (secret !== '' && !bucket.includes(secret)) bucket.push(secret);
    }
    secretsByLine.set(detection.line, bucket);
  }

  const findings: Finding[] = [];
  for (const detection of selectDetections(detections)) {
    if (isAllowlisted(detection, config)) continue;
    if (findings.length >= MAX_FINDINGS_PER_FILE) {
      logger.warn(
        `secrets: ${relPath} produced more than ${MAX_FINDINGS_PER_FILE} findings; the rest were dropped`,
      );
      break;
    }
    const lineSecrets = secretsByLine.get(detection.line) ?? [];
    const finding = buildFinding(relPath, detection, lineSecrets);
    if (finding === undefined) {
      // Unreachable unless redaction fails; reported without any file content.
      logger.error(
        `secrets: dropped a ${detection.ruleId} finding at ${relPath}:${detection.line} because its evidence could not be redacted`,
      );
      continue;
    }
    findings.push(finding);
  }
  return findings;
}

/**
 * Universal rejections applied to every tier: values that are references or
 * template slots rather than credentials, and values too short for core's
 * redaction to remove from the evidence line.
 */
function isReportable(detection: Detection): boolean {
  if (detection.allowlistValue !== undefined && isNonSecretReference(detection.allowlistValue)) {
    return false;
  }
  return !detection.secrets.some(
    (secret) =>
      secret !== '' &&
      secret.length < MIN_REDACTABLE_LENGTH &&
      detection.evidenceSource.includes(secret),
  );
}

function isAllowlisted(detection: Detection, config: SecretsConfig): boolean {
  if (config.allowlistRuleIds.has(detection.ruleId)) return true;
  if (detection.allowlistValue !== undefined) {
    if (config.allowlistValues.has(detection.allowlistValue)) return true;
  }
  return detection.secrets.some((secret) => config.allowlistValues.has(secret));
}

const TIER_ORDER = { structured: 0, heuristic: 1 } as const;

function overlaps(a: Span, b: Span): boolean {
  return a.start < b.end && b.start < a.end;
}

/**
 * Resolve competing matches: structured formats win, and a heuristic match
 * that covers text another rule already reported is dropped. Ordering is fixed
 * (tier, line, column, rule id) so the output is deterministic.
 */
function selectDetections(detections: readonly Detection[]): Detection[] {
  const ordered = [...detections].sort(
    (a, b) =>
      TIER_ORDER[a.tier] - TIER_ORDER[b.tier] ||
      a.line - b.line ||
      a.column - b.column ||
      a.ruleId.localeCompare(b.ruleId),
  );

  const kept: Detection[] = [];
  const keptByLine = new Map<number, Detection[]>();
  const seen = new Set<string>();

  for (const detection of ordered) {
    const identity = `${detection.ruleId}:${detection.line}:${detection.span.start}`;
    if (seen.has(identity)) continue;
    const onLine = keptByLine.get(detection.line) ?? [];
    if (
      detection.tier === 'heuristic' &&
      onLine.some(
        (other) => other.ruleId !== detection.ruleId && overlaps(other.span, detection.span),
      )
    ) {
      continue;
    }
    seen.add(identity);
    onLine.push(detection);
    keptByLine.set(detection.line, onLine);
    kept.push(detection);
  }
  return kept;
}

function buildFinding(
  relPath: string,
  detection: Detection,
  lineSecrets: readonly string[],
): Finding | undefined {
  const rule = ruleMeta(detection.ruleId);
  const finding = createFinding({
    ruleId: rule.id,
    title: rule.title,
    description: rule.description,
    severity: detection.severity ?? rule.severity,
    confidence: detection.confidence ?? rule.defaultConfidence,
    category: rule.category,
    file: relPath,
    line: detection.line,
    column: detection.column,
    ...(detection.endLine === undefined ? {} : { endLine: detection.endLine }),
    evidence: buildEvidence(detection.evidenceSource, lineSecrets),
    recommendation: rule.recommendation,
    references: [...(rule.references ?? [])],
    scanner: SCANNER_ID,
    ...(detection.metadata === undefined ? {} : { metadata: detection.metadata }),
  });

  return leaksSecret(finding, lineSecrets) ? undefined : finding;
}

/**
 * Build the evidence string: redact first, clip second.
 *
 * A secret sitting 3000 characters into a generated line would otherwise be
 * reported with 200 characters of unrelated prefix, so the line is windowed
 * around the redaction marker. The window is taken AFTER redaction — clipping
 * the raw line could cut another secret on that line in half and leave the
 * remainder behind, which whole-value redaction would no longer match.
 */
function buildEvidence(source: string, secrets: readonly string[]): string {
  const redacted = redactEvidence(source, secrets, Number.MAX_SAFE_INTEGER);
  const marker = redacted.indexOf(REDACTED);
  const windowed =
    marker > EVIDENCE_LEAD * 2 ? `…${redacted.slice(marker - EVIDENCE_LEAD)}` : redacted;
  // Second pass over an already-sanitized string: trims and truncates exactly
  // the way core does, with nothing left to replace.
  return redactEvidence(windowed, secrets, EVIDENCE_MAX_LENGTH);
}

/**
 * Final backstop for the no-leak invariant: check the finding's own string
 * fields (not their JSON encoding, which would hide escaped characters)
 * against every raw value found on the line.
 */
export function leaksSecret(finding: Finding, secrets: readonly string[]): boolean {
  const surface = [
    finding.id,
    finding.ruleId,
    finding.title,
    finding.description,
    finding.evidence,
    finding.recommendation,
    finding.file,
    finding.scanner,
    ...finding.references,
    ...Object.entries(finding.metadata ?? {}).flatMap(([key, value]) => [key, String(value)]),
  ].join(' ');
  return secrets.some((secret) => containsSecret(surface, secret));
}

/** Stable, content-independent ordering. */
function sortFindings(findings: readonly Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      a.file.localeCompare(b.file) ||
      (a.line ?? 0) - (b.line ?? 0) ||
      (a.column ?? 0) - (b.column ?? 0) ||
      a.ruleId.localeCompare(b.ruleId),
  );
}
