/**
 * Render an {@link InfraGraph} as a Mermaid `flowchart LR`. Node text comes
 * from scanned files (service names, image refs, host paths, ...) and is
 * therefore untrusted: it is escaped so it cannot break out of its quoted
 * label and inject extra diagram syntax (see {@link escapeMermaidLabel}).
 * Mermaid node ids are always synthetic (`n0`, `n1`, ...), never derived
 * from file content, so the id position needs no escaping at all.
 */
import type { GraphNode, GraphNodeKind, InfraGraph } from './types.js';

/**
 * Mermaid supports `#nnn;`/`#name;` numeric/named character references
 * inside labels. Escaping `#` first (before introducing our own `#quot;`
 * etc. sequences) prevents a crafted input containing the literal text
 * `#quot;` from being re-interpreted as a real quote once escaped.
 */
export function escapeMermaidLabel(label: string): string {
  return label
    .replace(/#/g, '#35;')
    .replace(/"/g, '#quot;')
    .replace(/</g, '#lt;')
    .replace(/>/g, '#gt;')
    .replace(/[\r\n\t]+/g, ' ')
    .trim();
}

function quoted(safeLabel: string): string {
  return `"${safeLabel}"`;
}

/** Node shape by kind: images/volumes/ports/network are shaped differently from the default box. */
function nodeShape(mermaidId: string, kind: GraphNodeKind, label: string): string {
  const text = quoted(escapeMermaidLabel(label));
  switch (kind) {
    case 'image':
      return `${mermaidId}((${text}))`;
    case 'volume':
    case 'hostPath':
      return `${mermaidId}[(${text})]`;
    case 'port':
      return `${mermaidId}{{${text}}}`;
    case 'network':
      return `${mermaidId}([${text}])`;
    case 'service':
    case 'workload':
    case 'container':
      return `${mermaidId}[${text}]`;
  }
}

const RISKY_CLASS = 'risky';

/** Shape-independent classDef per kind; `risky` (below) takes priority over this when both apply. */
const KIND_CLASS: Partial<Record<GraphNodeKind, string>> = {
  image: 'image',
  volume: 'volume',
  hostPath: 'volume',
  port: 'port',
  network: 'network',
};

const CLASS_DEFS: readonly string[] = [
  'classDef risky fill:#7f1d1d,stroke:#ef4444,color:#ffffff',
  'classDef image fill:#1e3a5f,stroke:#3b82f6,color:#ffffff',
  'classDef volume fill:#1e3a2f,stroke:#22c55e,color:#ffffff',
  'classDef port fill:#3a2f1e,stroke:#f59e0b,color:#ffffff',
  'classDef network fill:#33314b,stroke:#a78bfa,color:#ffffff',
];

/**
 * Nodes styled as risky: a hostPath (host-mount) target, anything flagged
 * `privileged`, or the source of a `host-network` edge — the three
 * conditions docs/architecture.md's "## Infrastructure graph" names.
 */
function riskyNodeIds(graph: InfraGraph): Set<string> {
  const risky = new Set<string>();
  for (const node of graph.nodes) {
    if (node.kind === 'hostPath' || node.attrs.privileged === true) risky.add(node.id);
  }
  for (const edge of graph.edges) {
    if (edge.kind === 'host-network') risky.add(edge.from);
  }
  return risky;
}

export function renderInfraGraphMermaid(graph: InfraGraph): string {
  const idMap = new Map<string, string>();
  graph.nodes.forEach((node, index) => idMap.set(node.id, `n${index}`));
  const risky = riskyNodeIds(graph);

  const lines: string[] = ['flowchart LR'];

  for (const node of graph.nodes) {
    const mermaidId = idMap.get(node.id);
    if (!mermaidId) continue;
    lines.push(`  ${nodeShape(mermaidId, node.kind, node.label)}`);
  }

  if (graph.nodes.length > 0) {
    lines.push(...CLASS_DEFS.map((def) => `  ${def}`));

    const idsByClass = new Map<string, string[]>();
    for (const node of graph.nodes) {
      const mermaidId = idMap.get(node.id);
      if (!mermaidId) continue;
      const className = risky.has(node.id) ? RISKY_CLASS : KIND_CLASS[node.kind];
      if (!className) continue;
      const list = idsByClass.get(className) ?? [];
      list.push(mermaidId);
      idsByClass.set(className, list);
    }
    for (const [className, ids] of idsByClass) {
      lines.push(`  class ${ids.join(',')} ${className}`);
    }
  }

  for (const edge of graph.edges) {
    const from = idMap.get(edge.from);
    const to = idMap.get(edge.to);
    if (!from || !to) continue; // defensive: buildInfraGraph never emits a dangling endpoint
    lines.push(`  ${from} -->|${edge.kind}| ${to}`);
  }

  return `${lines.join('\n')}\n`;
}
