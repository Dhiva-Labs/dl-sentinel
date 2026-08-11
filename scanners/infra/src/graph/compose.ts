/**
 * Compose → graph extraction. Reuses the scanner's own YAML plumbing
 * (`util/yaml-docs.ts`) for parsing and line resolution; only the
 * structural walk (which fields become which nodes/edges) is new — no
 * format is re-parsed from scratch here.
 */
import { posix } from 'node:path';
import { isComposeDoc, lineForPath, parseYamlFile } from '../util/yaml-docs.js';
import { isDockerSocketPath, looksLikeHostPathSource } from '../util/host-path.js';
import { isUnpinnedImageRef } from '../util/image-ref.js';
import type { GraphEdge, GraphNode, GraphNodeKind } from './types.js';
import { HOST_NODE_ID, pushUniqueNode, scopedNodeId, sharedNodeId } from './id.js';

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** A compose service's `build:` context, recorded for best-effort Dockerfile linking. */
export interface ComposeBuildContext {
  serviceNodeId: string;
  /** posix-normalized directory, relative to the repo root. */
  contextDir: string;
  /** Basename of the Dockerfile the build uses, e.g. `Dockerfile`, `Dockerfile.prod`. */
  dockerfileName: string;
}

export interface ComposeExtraction {
  nodes: GraphNode[];
  edges: GraphEdge[];
  buildContexts: ComposeBuildContext[];
}

interface ParsedComposePort {
  hostIp?: string;
  published?: number;
  target?: number;
  protocol: string;
}

function parseComposePort(raw: unknown): ParsedComposePort | undefined {
  if (isPlainObject(raw)) {
    const target = raw.target !== undefined ? Number(raw.target) : undefined;
    const published = raw.published !== undefined ? Number(raw.published) : undefined;
    const hostIp = typeof raw.host_ip === 'string' ? raw.host_ip : undefined;
    const protocol = typeof raw.protocol === 'string' ? raw.protocol.toLowerCase() : 'tcp';
    if (target === undefined && published === undefined) return undefined;
    return { hostIp, published, target, protocol };
  }
  if (typeof raw !== 'string' && typeof raw !== 'number') return undefined;
  const str = String(raw).trim();
  if (str.length === 0) return undefined;
  const parts = str.split(':');
  const last = parts[parts.length - 1] ?? '';
  const match = /^(\d+)(?:\/(tcp|udp))?$/i.exec(last);
  if (!match?.[1]) return undefined;
  const target = Number.parseInt(match[1], 10);
  const protocol = (match[2] ?? 'tcp').toLowerCase();
  if (parts.length === 1) return { target, protocol };
  if (parts.length === 2) return { published: Number(parts[0]), target, protocol };
  return { hostIp: parts[0], published: Number(parts[1]), target, protocol };
}

function formatPortLabel(p: ParsedComposePort): string {
  const portNum = p.published ?? p.target ?? '?';
  return `${portNum}/${p.protocol}`;
}

function portAttrs(p: ParsedComposePort): GraphNode['attrs'] {
  const attrs: GraphNode['attrs'] = { protocol: p.protocol };
  if (p.published !== undefined && Number.isFinite(p.published)) attrs.hostPort = p.published;
  if (p.target !== undefined && Number.isFinite(p.target)) attrs.containerPort = p.target;
  return attrs;
}

interface ParsedComposeVolume {
  source: string;
  readOnly: boolean;
  /** Path segment to the source value, for line lookup. */
  path: (string | number)[];
}

function parseComposeVolume(
  raw: unknown,
  serviceName: string,
  idx: number,
): ParsedComposeVolume | undefined {
  if (typeof raw === 'string') {
    const parts = raw.split(':');
    if (parts.length < 2) return undefined; // anonymous volume: container path only, no source
    const source = parts[0] ?? '';
    if (source.length === 0) return undefined;
    const mode = parts[2];
    const readOnly = mode !== undefined && mode.split(',').includes('ro');
    return { source, readOnly, path: ['services', serviceName, 'volumes', idx] };
  }
  if (isPlainObject(raw)) {
    const source = typeof raw.source === 'string' ? raw.source : undefined;
    if (!source) return undefined; // e.g. a tmpfs mount has no source at all
    const readOnly = raw.read_only === true;
    return { source, readOnly, path: ['services', serviceName, 'volumes', idx, 'source'] };
  }
  return undefined;
}

function resolveContextDir(composeFile: string, contextValue: string): string {
  return posix.normalize(posix.join(posix.dirname(composeFile), contextValue));
}

/**
 * Extract compose-sourced graph nodes/edges from one file. Returns
 * `undefined` when the file isn't parseable YAML or isn't compose-shaped
 * (no top-level `services` map) — the caller tries Kubernetes next, and
 * ultimately just skips a file nothing recognizes.
 */
export function extractCompose(file: string, text: string): ComposeExtraction | undefined {
  const parsed = parseYamlFile(text);
  if (!parsed) return undefined;
  const first = parsed.documents[0];
  if (!first) return undefined;
  const js = first.toJS() as unknown;
  if (!isComposeDoc(js)) return undefined;
  const services = js.services;
  if (!isPlainObject(services)) return undefined;

  const lineCounter = parsed.lineCounter;
  const lineAt = (path: (string | number)[]): number | undefined =>
    lineForPath(first, lineCounter, path);

  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const buildContexts: ComposeBuildContext[] = [];
  const serviceNames = new Set(Object.keys(services));
  let usesHostNode = false;

  for (const [name, rawService] of Object.entries(services)) {
    if (!isPlainObject(rawService)) continue;
    const serviceId = scopedNodeId('service', name, file);
    const privileged = rawService.privileged === true;

    nodes.push({
      id: serviceId,
      kind: 'service',
      label: name,
      source: { file, line: lineAt(['services', name]) },
      attrs: { privileged },
    });

    if (typeof rawService.image === 'string' && rawService.image.trim().length > 0) {
      const ref = rawService.image.trim();
      const imageId = sharedNodeId('image', ref);
      pushUniqueNode(nodes, {
        id: imageId,
        kind: 'image',
        label: ref,
        source: { file, line: lineAt(['services', name, 'image']) },
        attrs: { unpinned: isUnpinnedImageRef(ref) },
      });
      edges.push({ from: serviceId, to: imageId, kind: 'uses-image' });
    }

    const build = rawService.build;
    if (typeof build === 'string') {
      buildContexts.push({
        serviceNodeId: serviceId,
        contextDir: resolveContextDir(file, build),
        dockerfileName: 'Dockerfile',
      });
    } else if (isPlainObject(build) && typeof build.context === 'string') {
      buildContexts.push({
        serviceNodeId: serviceId,
        contextDir: resolveContextDir(file, build.context),
        dockerfileName:
          typeof build.dockerfile === 'string' ? posix.basename(build.dockerfile) : 'Dockerfile',
      });
    }

    if (Array.isArray(rawService.ports)) {
      rawService.ports.forEach((rawPort, idx) => {
        const parsedPort = parseComposePort(rawPort);
        if (!parsedPort) return;
        const label = formatPortLabel(parsedPort);
        const portId = scopedNodeId('port', label, file);
        pushUniqueNode(nodes, {
          id: portId,
          kind: 'port',
          label,
          source: { file, line: lineAt(['services', name, 'ports', idx]) },
          attrs: portAttrs(parsedPort),
        });
        edges.push({ from: serviceId, to: portId, kind: 'exposes' });
      });
    }

    if (Array.isArray(rawService.volumes)) {
      rawService.volumes.forEach((rawVol, idx) => {
        const mount = parseComposeVolume(rawVol, name, idx);
        if (!mount) return;
        const isHost = looksLikeHostPathSource(mount.source);
        const kind: GraphNodeKind = isHost ? 'hostPath' : 'volume';
        const volId = scopedNodeId(kind, mount.source, file);
        pushUniqueNode(nodes, {
          id: volId,
          kind,
          label: mount.source,
          source: { file, line: lineAt(mount.path) },
          attrs: isHost
            ? { readOnly: mount.readOnly, dockerSocket: isDockerSocketPath(mount.source) }
            : { readOnly: mount.readOnly },
        });
        edges.push({ from: serviceId, to: volId, kind: 'mounts' });
      });
    }

    if (rawService.network_mode === 'host') {
      usesHostNode = true;
      edges.push({ from: serviceId, to: HOST_NODE_ID, kind: 'host-network' });
    }
    if (privileged) {
      usesHostNode = true;
      edges.push({ from: serviceId, to: HOST_NODE_ID, kind: 'privileged' });
    }

    const dependsOn = rawService.depends_on;
    const depNames: string[] = Array.isArray(dependsOn)
      ? dependsOn.filter((d): d is string => typeof d === 'string')
      : isPlainObject(dependsOn)
        ? Object.keys(dependsOn)
        : [];
    for (const dep of depNames) {
      if (!serviceNames.has(dep)) continue; // dangling reference: best-effort, skip
      edges.push({ from: serviceId, to: scopedNodeId('service', dep, file), kind: 'depends-on' });
    }

    if (Array.isArray(rawService.links)) {
      for (const rawLink of rawService.links) {
        if (typeof rawLink !== 'string') continue;
        const target = rawLink.split(':')[0]?.trim();
        if (!target || !serviceNames.has(target)) continue;
        edges.push({
          from: serviceId,
          to: scopedNodeId('service', target, file),
          kind: 'connects',
        });
      }
    }
  }

  if (usesHostNode) {
    pushUniqueNode(nodes, {
      id: HOST_NODE_ID,
      kind: 'network',
      label: 'host',
      source: { file },
      attrs: { synthesized: true },
    });
  }

  return { nodes, edges, buildContexts };
}
