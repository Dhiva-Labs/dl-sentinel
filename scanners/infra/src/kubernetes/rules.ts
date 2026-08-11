import type { Document, LineCounter } from 'yaml';
import type { Finding } from '@dl-sentinel/core';
import { ruleDef } from '../rules-meta.js';
import { buildFinding } from '../util/build-finding.js';
import { classifyHostPathSeverity, isDockerSocketPath } from '../util/host-path.js';
import { isUnpinnedImageRef } from '../util/image-ref.js';
import { isLiteralSecretValue } from '../util/secret-heuristic.js';
import { evidenceAt } from '../util/yaml-docs.js';

export type PathKey = string | number;

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export interface PodSpecRef {
  spec: Record<string, unknown>;
  basePath: PathKey[];
}

/**
 * Resolve the pod spec(s) embedded in a Kubernetes manifest document,
 * following each supported kind to where its `containers` list actually
 * lives. Kinds without a pod template (Service, ConfigMap, CRDs, ...)
 * resolve to no pod specs and simply produce no findings.
 *
 * Exported (alongside {@link collectContainers}) so the infra graph builder
 * (`../graph/kubernetes.ts`) can reuse the exact same kind-resolution logic
 * instead of re-deriving it — a pure, side-effect-free structural helper,
 * so exporting it does not change this scanner's behavior.
 */
export function resolvePodSpecs(doc: Record<string, unknown>): PodSpecRef[] {
  const kind = typeof doc.kind === 'string' ? doc.kind : undefined;
  const spec = isPlainObject(doc.spec) ? doc.spec : undefined;
  if (!kind || !spec) return [];

  switch (kind) {
    case 'Pod':
      return [{ spec, basePath: ['spec'] }];
    case 'Deployment':
    case 'StatefulSet':
    case 'DaemonSet':
    case 'Job': {
      const template = isPlainObject(spec.template) ? spec.template : undefined;
      const podSpec = template && isPlainObject(template.spec) ? template.spec : undefined;
      if (!podSpec) return [];
      return [{ spec: podSpec, basePath: ['spec', 'template', 'spec'] }];
    }
    case 'CronJob': {
      const jobTemplate = isPlainObject(spec.jobTemplate) ? spec.jobTemplate : undefined;
      const jobSpec = jobTemplate && isPlainObject(jobTemplate.spec) ? jobTemplate.spec : undefined;
      const template = jobSpec && isPlainObject(jobSpec.template) ? jobSpec.template : undefined;
      const podSpec = template && isPlainObject(template.spec) ? template.spec : undefined;
      if (!podSpec) return [];
      return [{ spec: podSpec, basePath: ['spec', 'jobTemplate', 'spec', 'template', 'spec'] }];
    }
    default:
      return [];
  }
}

export interface ContainerRef {
  container: Record<string, unknown>;
  path: PathKey[];
}

export function collectContainers(
  podSpec: Record<string, unknown>,
  basePath: PathKey[],
): ContainerRef[] {
  const refs: ContainerRef[] = [];
  for (const field of ['containers', 'initContainers'] as const) {
    const list = podSpec[field];
    if (!Array.isArray(list)) continue;
    list.forEach((entry, idx) => {
      if (isPlainObject(entry)) refs.push({ container: entry, path: [...basePath, field, idx] });
    });
  }
  return refs;
}

interface K8sCtx {
  doc: Document;
  lineCounter: LineCounter;
  lines: readonly string[];
  file: string;
}

function checkPrivileged(ctx: K8sCtx, ref: ContainerRef): Finding[] {
  const sc = ref.container.securityContext;
  if (!isPlainObject(sc) || sc.privileged !== true) return [];
  const def = ruleDef('I020');
  const { line, evidence } = evidenceAt({
    doc: ctx.doc,
    lineCounter: ctx.lineCounter,
    lines: ctx.lines,
    path: [...ref.path, 'securityContext', 'privileged'],
    fallback: `${pathLabel(ref.path)}.securityContext.privileged: true`,
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

function pathLabel(path: PathKey[]): string {
  return path.join('.');
}

function checkHostNamespaces(
  ctx: K8sCtx,
  podSpec: Record<string, unknown>,
  basePath: PathKey[],
): Finding[] {
  const def = ruleDef('I021');
  const findings: Finding[] = [];
  for (const field of ['hostNetwork', 'hostPID', 'hostIPC'] as const) {
    if (podSpec[field] !== true) continue;
    const path = [...basePath, field];
    const { line, evidence } = evidenceAt({
      doc: ctx.doc,
      lineCounter: ctx.lineCounter,
      lines: ctx.lines,
      path,
      fallback: `${pathLabel(path)}: true`,
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
        metadata: { field },
      }),
    );
  }
  return findings;
}

function checkHostPathVolumes(
  ctx: K8sCtx,
  podSpec: Record<string, unknown>,
  basePath: PathKey[],
): Finding[] {
  if (!Array.isArray(podSpec.volumes)) return [];
  const def = ruleDef('I022');
  const findings: Finding[] = [];
  podSpec.volumes.forEach((rawVolume, idx) => {
    if (!isPlainObject(rawVolume)) return;
    const hostPath = rawVolume.hostPath;
    if (!isPlainObject(hostPath) || typeof hostPath.path !== 'string') return;
    const severity = classifyHostPathSeverity(hostPath.path);
    const path = [...basePath, 'volumes', idx, 'hostPath', 'path'];
    const { line, evidence } = evidenceAt({
      doc: ctx.doc,
      lineCounter: ctx.lineCounter,
      lines: ctx.lines,
      path,
      fallback: `${pathLabel(path)}: ${hostPath.path}`,
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
        metadata: { hostPath: hostPath.path, dockerSocket: isDockerSocketPath(hostPath.path) },
      }),
    );
  });
  return findings;
}

/** Effective value of a securityContext field, container level winning over pod level. */
function effective<T>(
  containerSc: Record<string, unknown> | undefined,
  podSc: Record<string, unknown> | undefined,
  field: string,
): T | undefined {
  if (containerSc && field in containerSc) return containerSc[field] as T;
  if (podSc && field in podSc) return podSc[field] as T;
  return undefined;
}

function checkRunAsNonRoot(
  ctx: K8sCtx,
  ref: ContainerRef,
  podSecurityContext: Record<string, unknown> | undefined,
): Finding[] {
  const containerSc = isPlainObject(ref.container.securityContext)
    ? ref.container.securityContext
    : undefined;
  const runAsNonRoot = effective<boolean>(containerSc, podSecurityContext, 'runAsNonRoot');
  const runAsUser = effective<number>(containerSc, podSecurityContext, 'runAsUser');

  const nonRootAbsent = runAsNonRoot === undefined;
  const userIsRootOrAbsent = runAsUser === undefined || runAsUser === 0;
  if (!(nonRootAbsent && userIsRootOrAbsent)) return [];

  const def = ruleDef('I023');
  const path = [...ref.path, 'securityContext'];
  const { line, evidence } = evidenceAt({
    doc: ctx.doc,
    lineCounter: ctx.lineCounter,
    lines: ctx.lines,
    path,
    fallback: `${pathLabel(ref.path)}: no runAsNonRoot, no non-root runAsUser`,
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

function checkAllowPrivilegeEscalation(ctx: K8sCtx, ref: ContainerRef): Finding[] {
  const sc = ref.container.securityContext;
  const allowPrivilegeEscalation = isPlainObject(sc) ? sc.allowPrivilegeEscalation : undefined;
  if (allowPrivilegeEscalation === false) return [];

  const def = ruleDef('I024');
  const path = [...ref.path, 'securityContext', 'allowPrivilegeEscalation'];
  const { line, evidence } = evidenceAt({
    doc: ctx.doc,
    lineCounter: ctx.lineCounter,
    lines: ctx.lines,
    path,
    fallback: `${pathLabel(ref.path)}.securityContext.allowPrivilegeEscalation: not set to false`,
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

const CRITICAL_CAPS = new Set(['SYS_ADMIN', 'ALL']);
const HIGH_CAPS = new Set(['NET_ADMIN', 'SYS_PTRACE']);

function checkAddedCapabilities(ctx: K8sCtx, ref: ContainerRef): Finding[] {
  const sc = ref.container.securityContext;
  const capabilities = isPlainObject(sc) ? sc.capabilities : undefined;
  const add = isPlainObject(capabilities) ? capabilities.add : undefined;
  if (!Array.isArray(add)) return [];

  const def = ruleDef('I025');
  const findings: Finding[] = [];
  add.forEach((rawCap, idx) => {
    if (typeof rawCap !== 'string') return;
    const cap = rawCap.trim().toUpperCase();
    const severity: 'critical' | 'high' | 'low' = CRITICAL_CAPS.has(cap)
      ? 'critical'
      : HIGH_CAPS.has(cap)
        ? 'high'
        : 'low';
    const path = [...ref.path, 'securityContext', 'capabilities', 'add', idx];
    const { line, evidence } = evidenceAt({
      doc: ctx.doc,
      lineCounter: ctx.lineCounter,
      lines: ctx.lines,
      path,
      fallback: `${pathLabel(ref.path)}.securityContext.capabilities.add: ${rawCap}`,
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

function checkResourceLimits(ctx: K8sCtx, ref: ContainerRef): Finding[] {
  const resources = ref.container.resources;
  const limits = isPlainObject(resources) ? resources.limits : undefined;
  if (limits !== undefined && limits !== null) return [];

  const def = ruleDef('I026');
  const { line, evidence } = evidenceAt({
    doc: ctx.doc,
    lineCounter: ctx.lineCounter,
    lines: ctx.lines,
    path: ref.path,
    fallback: `${pathLabel(ref.path)}: no resources.limits`,
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

function checkUnpinnedImage(ctx: K8sCtx, ref: ContainerRef): Finding[] {
  const image = ref.container.image;
  if (typeof image !== 'string' || !isUnpinnedImageRef(image)) return [];

  const def = ruleDef('I027');
  const path = [...ref.path, 'image'];
  const { line, evidence } = evidenceAt({
    doc: ctx.doc,
    lineCounter: ctx.lineCounter,
    lines: ctx.lines,
    path,
    fallback: `${pathLabel(path)}: ${image}`,
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

function checkEnvSecrets(ctx: K8sCtx, ref: ContainerRef): Finding[] {
  if (!Array.isArray(ref.container.env)) return [];
  const def = ruleDef('I028');
  const findings: Finding[] = [];
  ref.container.env.forEach((rawEntry, idx) => {
    if (!isPlainObject(rawEntry)) return;
    if (rawEntry.valueFrom !== undefined) return; // secretKeyRef/configMapKeyRef/fieldRef: negative
    const name = rawEntry.name;
    const value = rawEntry.value;
    if (typeof name !== 'string') return;
    if (value !== undefined && typeof value !== 'string') return;
    if (!isLiteralSecretValue(name, value as string | undefined)) return;

    const path = [...ref.path, 'env', idx, 'value'];
    const { line, evidence } = evidenceAt({
      doc: ctx.doc,
      lineCounter: ctx.lineCounter,
      lines: ctx.lines,
      path,
      fallback: `${pathLabel(ref.path)}.env[${idx}]: ${name}=${String(value)}`,
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
        secrets: value !== undefined ? [value as string] : [],
      }),
    );
  });
  return findings;
}

/** Scan every Kubernetes manifest document in a (possibly multi-doc) stream. */
export function scanKubernetes(
  docs: readonly { doc: Document; js: unknown }[],
  lineCounter: LineCounter,
  lines: string[],
  file: string,
): Finding[] {
  const findings: Finding[] = [];

  for (const { doc, js } of docs) {
    if (!isPlainObject(js)) continue;
    const ctx: K8sCtx = { doc, lineCounter, lines, file };
    const podSpecs = resolvePodSpecs(js);

    for (const { spec: podSpec, basePath } of podSpecs) {
      const podSecurityContext = isPlainObject(podSpec.securityContext)
        ? podSpec.securityContext
        : undefined;

      findings.push(...checkHostNamespaces(ctx, podSpec, basePath));
      findings.push(...checkHostPathVolumes(ctx, podSpec, basePath));

      for (const containerRef of collectContainers(podSpec, basePath)) {
        findings.push(...checkPrivileged(ctx, containerRef));
        findings.push(...checkRunAsNonRoot(ctx, containerRef, podSecurityContext));
        findings.push(...checkAllowPrivilegeEscalation(ctx, containerRef));
        findings.push(...checkAddedCapabilities(ctx, containerRef));
        findings.push(...checkResourceLimits(ctx, containerRef));
        findings.push(...checkUnpinnedImage(ctx, containerRef));
        findings.push(...checkEnvSecrets(ctx, containerRef));
      }
    }
  }

  return findings;
}
