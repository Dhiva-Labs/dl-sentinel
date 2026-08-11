import type { Category, Confidence, RuleMeta, ScannerPlugin, Severity } from '@dl-sentinel/core';
import { SEVERITY_ORDER } from '@dl-sentinel/core';
import { BUILTIN_SCANNERS } from '@dl-sentinel/preset';
import { CliUsageError, parseFlags } from '../args.js';
import type { ColorFns } from '../colors.js';
import { makeColors, shouldColor } from '../colors.js';
import { EXIT } from '../exit-codes.js';
import type { CliIO } from '../io.js';
import { parseFormat, parseScannerList } from '../parse.js';
import { rulesHelp } from '../usage.js';

const RULES_FORMATS = ['terminal', 'json'] as const;

interface RuleRow {
  id: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  category: Category;
  scanner: string;
  compliance?: RuleMeta['compliance'];
}

/** `sentinel rules` — list every rule from the built-in scanners. */
export function runRules(argv: readonly string[], io: CliIO): number {
  const parsed = parseFlags(argv, [
    { name: 'format', takesValue: true },
    { name: 'scanners', takesValue: true },
    { name: 'no-color', takesValue: false },
    { name: 'help', takesValue: false, aliases: ['h'] },
  ]);

  if (parsed.bools.has('help')) {
    io.stdout(`${rulesHelp()}\n`);
    return EXIT.OK;
  }
  if (parsed.positionals.length > 0) {
    throw new CliUsageError(
      `rules takes no positional arguments (got "${parsed.positionals[0] ?? ''}")`,
    );
  }

  const format = parseFormat(parsed.values.get('format'), RULES_FORMATS);
  const filter = parseScannerList(parsed.values.get('scanners'));
  const scanners =
    filter === undefined
      ? [...BUILTIN_SCANNERS]
      : BUILTIN_SCANNERS.filter((scanner) => filter.includes(scanner.id));

  if (format === 'json') {
    io.stdout(`${JSON.stringify(toRows(scanners), null, 2)}\n`);
    return EXIT.OK;
  }

  const colors = makeColors(
    shouldColor({ noColorFlag: parsed.bools.has('no-color'), env: io.env, isTTY: io.stdoutIsTTY }),
  );
  io.stdout(`${renderTable(scanners, colors)}\n`);
  return EXIT.OK;
}

function toRows(scanners: readonly ScannerPlugin[]): RuleRow[] {
  const rows: RuleRow[] = [];
  for (const scanner of scanners) {
    for (const rule of scanner.rules) {
      rows.push({
        id: rule.id,
        title: rule.title,
        severity: rule.severity,
        confidence: rule.defaultConfidence,
        category: rule.category,
        scanner: scanner.id,
        // Omitted (never a key with an `undefined` value survives
        // JSON.stringify) for rules with no canonical compliance mapping.
        compliance: rule.compliance,
      });
    }
  }
  return rows;
}

/**
 * Compact "CWE-89 · A03:2021" style label for a rule's compliance mapping.
 * Returns undefined when the rule has none, so callers can omit the segment
 * entirely rather than print an empty one.
 */
function complianceLabel(compliance: RuleMeta['compliance']): string | undefined {
  const parts: string[] = [];
  if (compliance?.cwe && compliance.cwe.length > 0) parts.push(compliance.cwe.join(', '));
  if (compliance?.owasp && compliance.owasp.length > 0) parts.push(compliance.owasp.join(', '));
  return parts.length > 0 ? parts.join(' · ') : undefined;
}

function severityPaint(colors: ColorFns, severity: Severity): (text: string) => string {
  switch (severity) {
    case 'critical':
      return colors.red;
    case 'high':
      return colors.magenta;
    case 'medium':
      return colors.yellow;
    case 'low':
      return colors.cyan;
    case 'info':
      return colors.gray;
  }
}

function renderTable(scanners: readonly ScannerPlugin[], colors: ColorFns): string {
  const allRules = scanners.flatMap((scanner) => scanner.rules);
  const idWidth = Math.max(2, ...allRules.map((rule) => rule.id.length));
  const sevWidth = Math.max(...SEVERITY_ORDER.map((severity) => severity.length));
  const confWidth = Math.max('high'.length, 'medium'.length, 'low'.length);
  const catWidth = Math.max(3, ...allRules.map((rule) => rule.category.length));

  const lines: string[] = [];
  let total = 0;
  for (const scanner of scanners) {
    lines.push('');
    lines.push(
      `${colors.bold(colors.cyan(scanner.id))} ${colors.dim(
        `(${scanner.rules.length} rule${scanner.rules.length === 1 ? '' : 's'})`,
      )}`,
    );
    for (const rule of scanner.rules) {
      total += 1;
      const id = rule.id.padEnd(idWidth);
      const severity = severityPaint(colors, rule.severity)(rule.severity.padEnd(sevWidth));
      const confidence = colors.dim(rule.defaultConfidence.padEnd(confWidth));
      const category = rule.category.padEnd(catWidth);
      const compliance = complianceLabel(rule.compliance);
      const complianceSuffix = compliance ? `  ${colors.dim(compliance)}` : '';
      lines.push(
        `  ${id}  ${severity}  ${confidence}  ${category}  ${rule.title}${complianceSuffix}`,
      );
    }
  }
  lines.push('');
  lines.push(
    colors.dim(
      `Total: ${total} rule${total === 1 ? '' : 's'} across ${scanners.length} scanner${
        scanners.length === 1 ? '' : 's'
      }`,
    ),
  );
  return lines.join('\n');
}
