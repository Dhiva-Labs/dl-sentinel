import type { Document, LineCounter } from 'yaml';
import type { Finding } from '@dl-sentinel/core';
import { ruleDef } from '../rules-meta.js';
import { buildFinding } from '../util/build-finding.js';
import {
  classifyHostPathSeverity,
  isDockerSocketPath,
  looksLikeHostPathSource,
} from '../util/host-path.js';
import { isLiteralSecretValue } from '../util/secret-heuristic.js';
import { evidenceAt } from '../util/yaml-docs.js';

const SENSITIVE_DB_PORTS = new Set([5432, 3306, 6379, 27017]);

interface ComposeCtx {
  doc: Document;
  lineCounter: LineCounter;
  lines: readonly string[];
  file: string;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function checkPrivileged(
  ctx: ComposeCtx,
  name: string,
  service: Record<string, unknown>,
): Finding[] {
  if (service.privileged !== true) return [];
  const def = ruleDef('I010');
  const { line, evidence } = evidenceAt({
    doc: ctx.doc,
    lineCounter: ctx.lineCounter,
    lines: ctx.lines,
    path: ['services', name, 'privileged'],
    fallback: `services.${name}.privileged: true`,
  });
  return [
    buildFinding({
      ruleId: def.id,
      title: def.title,
      description: def.description,
      recommendation: def.recommendation,
      references: def.references,
      category: def.category,
      severity: def.severity,
      confidence: def.defaultConfidence,
      file: ctx.file,
      line,
      evidence,
    }),
  ];
}

function checkHostNetwork(
  ctx: ComposeCtx,
  name: string,
  service: Record<string, unknown>,
): Finding[] {
  if (service.network_mode !== 'host') return [];
  const def = ruleDef('I011');
  const { line, evidence } = evidenceAt({
    doc: ctx.doc,
    lineCounter: ctx.lineCounter,
    lines: ctx.lines,
    path: ['services', name, 'network_mode'],
    fallback: `services.${name}.network_mode: host`,
  });
  return [
    buildFinding({
      ruleId: def.id,
      title: def.title,
      description: def.description,
      recommendation: def.recommendation,
      references: def.references,
      category: def.category,
      severity: def.severity,
      confidence: def.defaultConfidence,
      file: ctx.file,
      line,
      evidence,
    }),
  ];
}

interface HostMount {
  source: string;
  /** Path to the node best representing this mount's source, for line lookup. */
  path: (string | number)[];
  fallback: string;
}

function collectHostMounts(name: string, volumes: unknown): HostMount[] {
  if (!Array.isArray(volumes)) return [];
  const mounts: HostMount[] = [];
  volumes.forEach((entry, idx) => {
    if (typeof entry === 'string') {
      const parts = entry.split(':');
      if (parts.length < 2) return; // anonymous volume (container path only); no host source
      const source = parts[0] ?? '';
      if (!looksLikeHostPathSource(source)) return; // named volume reference, not a host path
      mounts.push({
        source,
        path: ['services', name, 'volumes', idx],
        fallback: `services.${name}.volumes: ${entry}`,
      });
      return;
    }
    if (isPlainObject(entry)) {
      const type = typeof entry.type === 'string' ? entry.type : undefined;
      const source = typeof entry.source === 'string' ? entry.source : undefined;
      if (!source) return;
      const isBind = type === 'bind' || (type === undefined && looksLikeHostPathSource(source));
      if (!isBind) return;
      mounts.push({
        source,
        path: ['services', name, 'volumes', idx, 'source'],
        fallback: `services.${name}.volumes[${idx}].source: ${source}`,
      });
    }
  });
  return mounts;
}

function checkHostMounts(
  ctx: ComposeCtx,
  name: string,
  service: Record<string, unknown>,
): Finding[] {
  const def = ruleDef('I012');
  const findings: Finding[] = [];
  for (const mount of collectHostMounts(name, service.volumes)) {
    const severity = classifyHostPathSeverity(mount.source);
    const { line, evidence } = evidenceAt({
      doc: ctx.doc,
      lineCounter: ctx.lineCounter,
      lines: ctx.lines,
      path: mount.path,
      fallback: mount.fallback,
    });
    findings.push(
      buildFinding({
        ruleId: def.id,
        title: def.title,
        description: def.description,
        recommendation: def.recommendation,
        references: def.references,
        category: def.category,
        severity,
        confidence: def.defaultConfidence,
        file: ctx.file,
        line,
        evidence,
        metadata: { hostPath: mount.source, dockerSocket: isDockerSocketPath(mount.source) },
      }),
    );
  }
  return findings;
}

const CRITICAL_CAPS = new Set(['SYS_ADMIN', 'ALL']);
const HIGH_CAPS = new Set(['NET_ADMIN', 'SYS_PTRACE']);

function checkCapAdd(ctx: ComposeCtx, name: string, service: Record<string, unknown>): Finding[] {
  if (!Array.isArray(service.cap_add)) return [];
  const def = ruleDef('I013');
  const findings: Finding[] = [];
  service.cap_add.forEach((rawCap, idx) => {
    if (typeof rawCap !== 'string') return;
    const cap = rawCap.trim().toUpperCase();
    let severity: 'critical' | 'high' | undefined;
    if (CRITICAL_CAPS.has(cap)) severity = 'critical';
    else if (HIGH_CAPS.has(cap)) severity = 'high';
    if (!severity) return;
    const { line, evidence } = evidenceAt({
      doc: ctx.doc,
      lineCounter: ctx.lineCounter,
      lines: ctx.lines,
      path: ['services', name, 'cap_add', idx],
      fallback: `services.${name}.cap_add: ${rawCap}`,
    });
    findings.push(
      buildFinding({
        ruleId: def.id,
        title: def.title,
        description: def.description,
        recommendation: def.recommendation,
        references: def.references,
        category: def.category,
        severity,
        confidence: def.defaultConfidence,
        file: ctx.file,
        line,
        evidence,
        metadata: { capability: cap },
      }),
    );
  });
  return findings;
}

function checkEnvironmentSecrets(
  ctx: ComposeCtx,
  name: string,
  service: Record<string, unknown>,
): Finding[] {
  const env = service.environment;
  if (env === undefined || env === null) return [];
  const def = ruleDef('I014');
  const findings: Finding[] = [];

  const pairs: Array<{ key: string; value: string | undefined; path: (string | number)[] }> = [];
  if (Array.isArray(env)) {
    env.forEach((entry, idx) => {
      if (typeof entry !== 'string') return;
      const eq = entry.indexOf('=');
      if (eq === -1) return; // `- SOME_VAR` passthrough, no literal value present
      pairs.push({
        key: entry.slice(0, eq),
        value: entry.slice(eq + 1),
        path: ['services', name, 'environment', idx],
      });
    });
  } else if (isPlainObject(env)) {
    for (const [key, value] of Object.entries(env)) {
      if (value === undefined || value === null) continue;
      pairs.push({ key, value: String(value), path: ['services', name, 'environment', key] });
    }
  }

  for (const pair of pairs) {
    if (!isLiteralSecretValue(pair.key, pair.value)) continue;
    const { line, evidence } = evidenceAt({
      doc: ctx.doc,
      lineCounter: ctx.lineCounter,
      lines: ctx.lines,
      path: pair.path,
      fallback: `services.${name}.environment.${pair.key}: ${pair.value}`,
    });
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
        file: ctx.file,
        line,
        evidence,
        secrets: pair.value !== undefined ? [pair.value] : [],
      }),
    );
  }
  return findings;
}

function checkResourceLimits(
  ctx: ComposeCtx,
  name: string,
  service: Record<string, unknown>,
): Finding[] {
  const deploy = isPlainObject(service.deploy) ? service.deploy : undefined;
  const resources = deploy && isPlainObject(deploy.resources) ? deploy.resources : undefined;
  const limits = resources?.limits;
  if (limits !== undefined && limits !== null) return [];

  const def = ruleDef('I015');
  const { line, evidence } = evidenceAt({
    doc: ctx.doc,
    lineCounter: ctx.lineCounter,
    lines: ctx.lines,
    path: ['services', name],
    fallback: `services.${name}: no deploy.resources.limits`,
  });
  return [
    buildFinding({
      ruleId: def.id,
      title: def.title,
      description: def.description,
      recommendation: def.recommendation,
      references: def.references,
      category: def.category,
      severity: def.severity,
      confidence: def.defaultConfidence,
      file: ctx.file,
      line,
      evidence,
      metadata: { service: name },
    }),
  ];
}

interface ParsedPort {
  hostIp?: string;
  published?: number;
  target?: number;
}

function stripProtocol(value: string): string {
  return value.split('/')[0] ?? value;
}

function parsePortEntry(raw: unknown): ParsedPort | undefined {
  if (isPlainObject(raw)) {
    const target = raw.target !== undefined ? Number(raw.target) : undefined;
    const published = raw.published !== undefined ? Number(raw.published) : undefined;
    const hostIp = typeof raw.host_ip === 'string' ? raw.host_ip : undefined;
    return { hostIp, published, target };
  }
  if (typeof raw !== 'string' && typeof raw !== 'number') return undefined;
  const str = String(raw);
  const parts = str.split(':');
  if (parts.length === 1) {
    const target = Number(stripProtocol(parts[0] ?? ''));
    return { target };
  }
  if (parts.length === 2) {
    const published = Number(parts[0]);
    const target = Number(stripProtocol(parts[1] ?? ''));
    return { published, target };
  }
  // host_ip:published:target
  const hostIp = parts[0];
  const published = Number(parts[1]);
  const target = Number(stripProtocol(parts[2] ?? ''));
  return { hostIp, published, target };
}

function isUnrestrictedHostIp(hostIp: string | undefined): boolean {
  return (
    hostIp === undefined || hostIp.trim().length === 0 || hostIp === '0.0.0.0' || hostIp === '::'
  );
}

function checkPublishedDbPorts(
  ctx: ComposeCtx,
  name: string,
  service: Record<string, unknown>,
): Finding[] {
  if (!Array.isArray(service.ports)) return [];
  const def = ruleDef('I016');
  const findings: Finding[] = [];
  service.ports.forEach((rawPort, idx) => {
    const parsed = parsePortEntry(rawPort);
    if (!parsed) return;
    if (!isUnrestrictedHostIp(parsed.hostIp)) return;
    const sensitive =
      (parsed.published !== undefined && SENSITIVE_DB_PORTS.has(parsed.published)) ||
      (parsed.target !== undefined && SENSITIVE_DB_PORTS.has(parsed.target));
    if (!sensitive) return;

    const { line, evidence } = evidenceAt({
      doc: ctx.doc,
      lineCounter: ctx.lineCounter,
      lines: ctx.lines,
      path: ['services', name, 'ports', idx],
      fallback: `services.${name}.ports: ${JSON.stringify(rawPort)}`,
    });
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
        file: ctx.file,
        line,
        evidence,
      }),
    );
  });
  return findings;
}

export function scanCompose(
  doc: Document,
  lineCounter: LineCounter,
  lines: string[],
  file: string,
): Finding[] {
  const js = doc.toJS() as unknown;
  if (!isPlainObject(js) || !isPlainObject(js.services)) return [];

  const ctx: ComposeCtx = { doc, lineCounter, lines, file };
  const findings: Finding[] = [];

  for (const [name, rawService] of Object.entries(js.services)) {
    if (!isPlainObject(rawService)) continue;
    findings.push(...checkPrivileged(ctx, name, rawService));
    findings.push(...checkHostNetwork(ctx, name, rawService));
    findings.push(...checkHostMounts(ctx, name, rawService));
    findings.push(...checkCapAdd(ctx, name, rawService));
    findings.push(...checkEnvironmentSecrets(ctx, name, rawService));
    findings.push(...checkResourceLimits(ctx, name, rawService));
    findings.push(...checkPublishedDbPorts(ctx, name, rawService));
  }

  return findings;
}
