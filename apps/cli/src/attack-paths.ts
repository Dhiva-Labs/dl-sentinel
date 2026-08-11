/**
 * `sentinel scan --paths` support: building the infrastructure graph for the
 * scan target, and rendering the "Attack paths" section for the human-readable
 * formats.
 *
 * The section is presentation only. Attack paths re-present findings the report
 * already contains, so they never change the stats and never change the exit
 * code (docs/attack-paths.md "Exit codes"). `--format json` needs nothing from
 * this module: `report.attackPaths` serializes on its own. `--format sarif` is
 * deliberately untouched — SARIF describes results, and a candidate chain is
 * not a result.
 */
import { readFile } from 'node:fs/promises';
import type { AttackPath, AttackPathStep, Finding } from '@dl-sentinel/core';
import { pathConfidenceLabel } from '@dl-sentinel/attack-paths';
import { buildInfraGraph, type InfraGraph, type InfraGraphFile } from '@dl-sentinel/scanner-infra';
import { discoverInfraFiles } from './infra-discovery.js';

/** Terminal wrap column; matches the width the rest of the CLI's prose assumes. */
const WRAP = 96;

/**
 * Build the deployment graph for `target`, reusing the same discovery
 * `sentinel graph` uses. Best-effort throughout: a file that cannot be read is
 * skipped rather than failing the scan, and a target with no infrastructure
 * simply yields an empty graph (which degrades path confidence rather than
 * inventing linkage).
 */
export async function buildTargetGraph(target: string): Promise<InfraGraph> {
  const discovered = await discoverInfraFiles(target);
  const files: InfraGraphFile[] = [];
  for (const file of discovered) {
    try {
      files.push({ relPath: file.relPath, text: await readFile(file.absPath, 'utf8') });
    } catch {
      continue; // unreadable file: it contributes nothing, the scan carries on
    }
  }
  return buildInfraGraph(files);
}

/** `file:line` for a step, using the line from the finding it was built on. */
function location(step: AttackPathStep, findingsById: ReadonlyMap<string, Finding>): string {
  const line = findingsById.get(step.findingId)?.line;
  return line === undefined ? step.file : `${step.file}:${String(line)}`;
}

function indexFindings(findings: readonly Finding[]): Map<string, Finding> {
  return new Map(findings.map((finding) => [finding.id, finding]));
}

/** Greedy word wrap with a fixed left indent on every produced line. */
function wrap(text: string, indent: string, width = WRAP): string[] {
  const limit = Math.max(20, width - indent.length);
  const lines: string[] = [];
  let current = '';
  for (const word of text.split(/\s+/).filter((part) => part.length > 0)) {
    if (current.length === 0) current = word;
    else if (current.length + 1 + word.length <= limit) current = `${current} ${word}`;
    else {
      lines.push(`${indent}${current}`);
      current = word;
    }
  }
  if (current.length > 0) lines.push(`${indent}${current}`);
  return lines;
}

/**
 * The terminal "Attack paths" section, or `''` when there is nothing to show —
 * an empty section is noise, and the caller reports the empty case on stderr.
 */
export function renderAttackPathsTerminal(
  paths: readonly AttackPath[],
  findings: readonly Finding[],
): string {
  if (paths.length === 0) return '';
  const findingsById = indexFindings(findings);
  const lines: string[] = [];
  lines.push(`Attack paths (${String(paths.length)})`);
  lines.push('Candidate chains for review. DL Sentinel does not verify exploitability.');
  lines.push('');

  paths.forEach((path, index) => {
    const confidence = pathConfidenceLabel(path.confidence);
    lines.push(
      `  ${String(index + 1)}. ${path.id.split(':')[0] ?? path.id}  ${path.severity}  ${confidence}`,
    );
    lines.push(`     ${path.title}`);
    path.steps.forEach((step, stepIndex) => {
      lines.push(
        `     ${String(stepIndex + 1)}. ${step.role.padEnd(10)} ${step.ruleId}  ${location(step, findingsById)}`,
      );
      lines.push(...wrap(step.note, '        '));
    });
    lines.push(...wrap(path.narrative, '     '));
    lines.push('');
  });

  // Drop the trailing blank so the section joins cleanly onto the report.
  while (lines[lines.length - 1] === '') lines.pop();
  return lines.join('\n');
}

/** The markdown "Attack paths" section, or `''` when there is nothing to show. */
export function renderAttackPathsMarkdown(
  paths: readonly AttackPath[],
  findings: readonly Finding[],
): string {
  if (paths.length === 0) return '';
  const findingsById = indexFindings(findings);
  const lines: string[] = [];
  lines.push('## Attack paths');
  lines.push('');
  lines.push(
    'Candidate chains correlated from the findings above. These are combinations worth ' +
      'reviewing — DL Sentinel does not verify exploitability, and path confidence never ' +
      'exceeds `likely`.',
  );
  lines.push('');

  for (const path of paths) {
    const correlation = path.id.split(':')[0] ?? path.id;
    lines.push(`### ${path.severity.toUpperCase()} ${correlation} — ${path.title}`);
    lines.push('');
    lines.push(`- **Confidence:** ${pathConfidenceLabel(path.confidence)}`);
    lines.push(`- **Path id:** \`${path.id}\``);
    lines.push('');
    lines.push('| # | Role | Rule | Location | Note |');
    lines.push('| --- | --- | --- | --- | --- |');
    path.steps.forEach((step, index) => {
      lines.push(
        `| ${String(index + 1)} | ${step.role} | ${step.ruleId} | \`${location(step, findingsById)}\` | ${step.note} |`,
      );
    });
    lines.push('');
    lines.push(path.narrative);
    lines.push('');
  }

  while (lines[lines.length - 1] === '') lines.pop();
  return lines.join('\n');
}
