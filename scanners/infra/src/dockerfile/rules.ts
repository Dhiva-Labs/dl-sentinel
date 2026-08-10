import type { Finding } from '@dl-sentinel/core';
import { ruleDef } from '../rules-meta.js';
import { buildFinding } from '../util/build-finding.js';
import { isUnpinnedImageRef } from '../util/image-ref.js';
import { isLiteralSecretValue } from '../util/secret-heuristic.js';
import { isRootUser, parseDockerfile, type DockerInstruction } from './parse.js';

const ADMIN_PORTS = new Set([22, 23, 2375]);

/** Split a `KEY=value KEY2="value 2"` style argument string into pairs. */
function tokenizeKeyValuePairs(text: string): Array<{ name: string; value: string }> {
  const pairs: Array<{ name: string; value: string }> = [];
  const n = text.length;
  let i = 0;
  while (i < n) {
    while (i < n && /\s/.test(text[i] ?? '')) i++;
    if (i >= n) break;

    let name = '';
    while (i < n && text[i] !== '=' && !/\s/.test(text[i] ?? '')) {
      name += text[i];
      i++;
    }
    if (text[i] !== '=') {
      // No '=' for this token (malformed pair) — skip it defensively.
      while (i < n && !/\s/.test(text[i] ?? '')) i++;
      continue;
    }
    i++; // skip '='

    let value = '';
    const quote = text[i];
    if (quote === '"' || quote === "'") {
      i++;
      while (i < n && text[i] !== quote) {
        if (text[i] === '\\' && i + 1 < n) {
          value += text[i + 1];
          i += 2;
        } else {
          value += text[i];
          i++;
        }
      }
      i++; // skip closing quote
    } else {
      while (i < n && !/\s/.test(text[i] ?? '')) {
        value += text[i];
        i++;
      }
    }
    pairs.push({ name, value });
  }
  return pairs;
}

function stripQuotes(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length >= 2) {
    const first = trimmed[0];
    const last = trimmed[trimmed.length - 1];
    if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
      return trimmed.slice(1, -1);
    }
  }
  return trimmed;
}

/** Parse ENV/ARG instruction args into name/value pairs (value undefined = no literal given). */
function parseEnvArgPairs(args: string): Array<{ name: string; value: string | undefined }> {
  const trimmed = args.trim();
  if (trimmed.length === 0) return [];

  if (trimmed.includes('=')) {
    return tokenizeKeyValuePairs(trimmed);
  }

  // Legacy single-pair form: `ENV NAME value` or bare `ARG NAME`.
  const firstSpace = trimmed.search(/\s/);
  if (firstSpace === -1) return [{ name: trimmed, value: undefined }];
  const name = trimmed.slice(0, firstSpace);
  const value = stripQuotes(trimmed.slice(firstSpace + 1));
  return [{ name, value }];
}

/** curl/wget piped into a shell, possibly through intermediate pipe stages. */
function hasPipedRemoteInstall(argsText: string): boolean {
  if (/^\s*\[/.test(argsText)) return false; // exec-form JSON array: no shell pipe semantics
  const segments = argsText.split('|').map((s) => s.trim());
  if (segments.length < 2) return false;
  const hasDownloader = segments.slice(0, -1).some((seg) => /\b(curl|wget)\b/i.test(seg));
  const last = segments[segments.length - 1] ?? '';
  const endsInShell = /^(?:sudo\s+)?(sh|bash|zsh)\b/i.test(last);
  return hasDownloader && endsInShell;
}

/** Extract EXPOSE'd port numbers from instruction args (`80 443 22/tcp` -> [80, 443, 22]). */
function parseExposedPorts(argsText: string): number[] {
  const ports: number[] = [];
  for (const token of argsText.split(/\s+/).filter(Boolean)) {
    const match = /^(\d+)(?:\/(?:tcp|udp))?$/i.exec(token);
    if (match?.[1]) ports.push(Number.parseInt(match[1], 10));
  }
  return ports;
}

function checkAddRemoteUrl(inst: DockerInstruction, file: string): Finding | undefined {
  const tokens = inst.args.split(/\s+/).filter(Boolean);
  // ADD [--chown=..] [--chmod=..] <src>... <dest> — sources are every token but the last,
  // unless there's only one token (then it's the dest with an implicit missing source, which
  // is invalid Dockerfile syntax anyway; nothing to flag).
  const flagsStripped = tokens.filter((t) => !t.startsWith('--'));
  const sources = flagsStripped.slice(0, -1);
  const hasRemote = sources.some((s) => /^https?:\/\//i.test(s));
  if (!hasRemote) return undefined;
  const def = ruleDef('I002');
  return buildFinding({
    ruleId: def.id,
    title: def.title,
    description: def.description,
    recommendation: def.recommendation,
    references: def.references,
    category: def.category,
    severity: def.severity,
    confidence: def.defaultConfidence,
    file,
    line: inst.line,
    evidence: `ADD ${inst.args}`,
  });
}

function checkEnvArgSecret(inst: DockerInstruction, file: string): Finding[] {
  const findings: Finding[] = [];
  const def = ruleDef('I004');
  for (const { name, value } of parseEnvArgPairs(inst.args)) {
    if (!isLiteralSecretValue(name, value)) continue;
    findings.push(
      buildFinding({
        ruleId: def.id,
        title: def.title,
        description: def.description,
        recommendation: def.recommendation,
        references: def.references,
        category: def.category,
        severity: def.severity,
        confidence: def.defaultConfidence,
        file,
        line: inst.line,
        evidence: `${inst.instruction} ${inst.args}`,
        secrets: value !== undefined ? [value] : [],
      }),
    );
  }
  return findings;
}

function checkPipedRemoteInstall(inst: DockerInstruction, file: string): Finding | undefined {
  if (!hasPipedRemoteInstall(inst.args)) return undefined;
  const def = ruleDef('I005');
  return buildFinding({
    ruleId: def.id,
    title: def.title,
    description: def.description,
    recommendation: def.recommendation,
    references: def.references,
    category: def.category,
    severity: def.severity,
    confidence: def.defaultConfidence,
    file,
    line: inst.line,
    evidence: `RUN ${inst.args}`,
  });
}

function checkAdminPortExposed(inst: DockerInstruction, file: string): Finding | undefined {
  const ports = parseExposedPorts(inst.args).filter((p) => ADMIN_PORTS.has(p));
  if (ports.length === 0) return undefined;
  const def = ruleDef('I006');
  return buildFinding({
    ruleId: def.id,
    title: def.title,
    description: def.description,
    recommendation: def.recommendation,
    references: def.references,
    category: def.category,
    severity: def.severity,
    confidence: def.defaultConfidence,
    file,
    line: inst.line,
    evidence: `EXPOSE ${inst.args}`,
    metadata: { ports: ports.join(',') },
  });
}

export function scanDockerfile(text: string, file: string): Finding[] {
  const findings: Finding[] = [];
  const parsed = parseDockerfile(text);

  // I001 — container runs as root, evaluated once for the whole file against
  // the final stage (the one that actually produces the shipped image).
  const finalStage = parsed.stages[parsed.stages.length - 1];
  if (finalStage) {
    const lastUser = finalStage.lastUser;
    const runsAsRoot = !lastUser || isRootUser(lastUser.value);
    if (runsAsRoot) {
      const def = ruleDef('I001');
      findings.push(
        buildFinding({
          ruleId: def.id,
          title: def.title,
          description: def.description,
          recommendation: def.recommendation,
          references: def.references,
          category: def.category,
          severity: def.severity,
          confidence: def.defaultConfidence,
          file,
          line: lastUser ? lastUser.line : finalStage.fromLine,
          evidence: lastUser ? `USER ${lastUser.value}` : `FROM ${finalStage.image}`,
        }),
      );
    }
  }

  // I003 — unpinned base image, evaluated per stage (skipping stage-alias
  // references and the empty `scratch` pseudo-image).
  const def003 = ruleDef('I003');
  for (const stage of parsed.stages) {
    if (stage.isAlias) continue;
    if (stage.image.toLowerCase() === 'scratch') continue;
    if (!isUnpinnedImageRef(stage.image)) continue;
    findings.push(
      buildFinding({
        ruleId: def003.id,
        title: def003.title,
        description: def003.description,
        recommendation: def003.recommendation,
        references: def003.references,
        category: def003.category,
        severity: def003.severity,
        confidence: def003.defaultConfidence,
        file,
        line: stage.fromLine,
        evidence: `FROM ${stage.image}`,
      }),
    );
  }

  for (const inst of parsed.instructions) {
    switch (inst.instruction) {
      case 'ADD': {
        const finding = checkAddRemoteUrl(inst, file);
        if (finding) findings.push(finding);
        break;
      }
      case 'ENV':
      case 'ARG':
        findings.push(...checkEnvArgSecret(inst, file));
        break;
      case 'RUN': {
        const finding = checkPipedRemoteInstall(inst, file);
        if (finding) findings.push(finding);
        break;
      }
      case 'EXPOSE': {
        const finding = checkAdminPortExposed(inst, file);
        if (finding) findings.push(finding);
        break;
      }
      default:
        break;
    }
  }

  return findings;
}
