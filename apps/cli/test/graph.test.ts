import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { InfraGraph } from '@dl-sentinel/scanner-infra';
import { fixturePath } from '../../../tests/support/index.js';
import { EXIT } from '../src/exit-codes.js';
import { runCli } from './helpers.js';

const VULNERABLE = fixturePath('vulnerable-app');
const CLEAN = fixturePath('clean-app');

describe('graph — json output', () => {
  it('emits a parseable graph with the expected service/image/port nodes and a privileged edge', async () => {
    const { code, stdout, stderr } = await runCli(['graph', VULNERABLE, '--format', 'json']);
    expect(code).toBe(EXIT.OK);
    expect(stderr).toBe('');

    const graph = JSON.parse(stdout) as InfraGraph;
    expect(Array.isArray(graph.nodes)).toBe(true);
    expect(Array.isArray(graph.edges)).toBe(true);
    expect(graph.nodes.length).toBeGreaterThan(0);

    const byKindLabel = graph.nodes.map((n) => `${n.kind}:${n.label}`);
    expect(byKindLabel).toContain('service:app');
    expect(byKindLabel).toContain('image:vulnerable-app-fixture:latest');
    // The compose app service is privileged AND network_mode: host — both
    // best-effort-linked to the same synthesized host node.
    const privilegedEdges = graph.edges.filter((e) => e.kind === 'privileged');
    const hostNetworkEdges = graph.edges.filter((e) => e.kind === 'host-network');
    expect(privilegedEdges.length).toBeGreaterThan(0);
    expect(hostNetworkEdges.length).toBeGreaterThan(0);
    for (const edge of [...privilegedEdges, ...hostNetworkEdges]) {
      expect(graph.nodes.some((n) => n.id === edge.to && n.kind === 'network')).toBe(true);
    }

    // Every edge endpoint is a declared node (no dangling references).
    const ids = new Set(graph.nodes.map((n) => n.id));
    for (const edge of graph.edges) {
      expect(ids.has(edge.from)).toBe(true);
      expect(ids.has(edge.to)).toBe(true);
    }
  });

  it('defaults --format to json', async () => {
    const { stdout } = await runCli(['graph', VULNERABLE]);
    expect(() => JSON.parse(stdout)).not.toThrow();
  });
});

describe('graph — mermaid output', () => {
  it('contains the flowchart header and a risky class assignment', async () => {
    const { code, stdout } = await runCli(['graph', VULNERABLE, '--format', 'mermaid']);
    expect(code).toBe(EXIT.OK);
    expect(stdout.startsWith('flowchart LR\n')).toBe(true);
    expect(stdout).toMatch(/classDef risky/);
    expect(stdout).toMatch(/ risky\b/);
  });
});

describe('graph — clean-app (benign)', () => {
  it('produces a graph with nodes but no privileged or hostPath edges', async () => {
    const { code, stdout } = await runCli(['graph', CLEAN, '--format', 'json']);
    expect(code).toBe(EXIT.OK);
    const graph = JSON.parse(stdout) as InfraGraph;
    expect(graph.nodes.length).toBeGreaterThan(0);
    expect(graph.edges.filter((e) => e.kind === 'privileged')).toHaveLength(0);
    expect(graph.edges.filter((e) => e.kind === 'host-network')).toHaveLength(0);
    expect(graph.nodes.filter((n) => n.kind === 'hostPath')).toHaveLength(0);
  });
});

describe('graph — --output', () => {
  let tmp: string;
  beforeAll(() => {
    tmp = mkdtempSync(join(tmpdir(), 'dl-sentinel-cli-graph-'));
  });
  afterAll(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it('writes the graph to a file and leaves stdout empty', async () => {
    const dest = join(tmp, 'graph.json');
    const { code, stdout } = await runCli([
      'graph',
      VULNERABLE,
      '--format',
      'json',
      '--output',
      dest,
    ]);
    expect(code).toBe(EXIT.OK);
    expect(stdout).toBe('');
    const written = JSON.parse(readFileSync(dest, 'utf8')) as InfraGraph;
    expect(written.nodes.length).toBeGreaterThan(0);
  });

  it('reports a write error to an unwritable path as exit 2', async () => {
    const dest = join(tmp, 'no-such-dir', 'graph.json');
    const { code, stderr } = await runCli(['graph', CLEAN, '--output', dest]);
    expect(code).toBe(EXIT.ERROR);
    expect(stderr).toContain('cannot write');
  });
});

describe('graph — empty target', () => {
  let tmp: string;
  beforeAll(() => {
    tmp = mkdtempSync(join(tmpdir(), 'dl-sentinel-cli-graph-empty-'));
  });
  afterAll(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it('prints a friendly note to stderr and an empty-but-valid graph to stdout, exit 0', async () => {
    const { code, stdout, stderr } = await runCli(['graph', tmp, '--format', 'json']);
    expect(code).toBe(EXIT.OK);
    expect(stderr).toContain('No infrastructure definitions found');
    const graph = JSON.parse(stdout) as InfraGraph;
    expect(graph).toEqual({ nodes: [], edges: [] });
  });

  it('does the same for mermaid: a valid, minimal flowchart', async () => {
    const { code, stdout } = await runCli(['graph', tmp, '--format', 'mermaid']);
    expect(code).toBe(EXIT.OK);
    expect(stdout.trim()).toBe('flowchart LR');
  });
});

describe('graph — usage errors (exit 64)', () => {
  it('rejects an unknown flag', async () => {
    const { code, stderr } = await runCli(['graph', CLEAN, '--bogus']);
    expect(code).toBe(EXIT.USAGE);
    expect(stderr).toContain('Unknown option');
  });

  it('rejects an invalid --format', async () => {
    const { code, stderr } = await runCli(['graph', CLEAN, '--format', 'xml']);
    expect(code).toBe(EXIT.USAGE);
    expect(stderr).toContain('Invalid --format');
  });

  it('rejects more than one positional path', async () => {
    const { code } = await runCli(['graph', CLEAN, VULNERABLE]);
    expect(code).toBe(EXIT.USAGE);
  });

  it('maps a nonexistent target to a usage error', async () => {
    const { code, stderr } = await runCli([
      'graph',
      join(tmpdir(), 'dl-sentinel-does-not-exist-xyz'),
    ]);
    expect(code).toBe(EXIT.USAGE);
    expect(stderr).toContain('does not exist');
  });
});

describe('graph — --help', () => {
  it('prints usage and exits 0 without touching the filesystem', async () => {
    const { code, stdout } = await runCli(['graph', '--help']);
    expect(code).toBe(EXIT.OK);
    expect(stdout).toContain('Usage: sentinel graph');
  });
});
