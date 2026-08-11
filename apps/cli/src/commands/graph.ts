import { readFile, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import {
  buildInfraGraph,
  renderInfraGraphMermaid,
  type InfraGraphFile,
} from '@dl-sentinel/scanner-infra';
import { CliUsageError, parseFlags } from '../args.js';
import { EXIT } from '../exit-codes.js';
import type { CliIO } from '../io.js';
import { discoverInfraFiles } from '../infra-discovery.js';
import { parseFormat } from '../parse.js';
import { graphHelp } from '../usage.js';

const GRAPH_FORMATS = ['json', 'mermaid'] as const;
type GraphFormat = (typeof GRAPH_FORMATS)[number];

/**
 * `sentinel graph [path]` — build the deployment-surface graph
 * (docs/architecture.md "## Infrastructure graph") from the Compose/
 * Kubernetes/Dockerfile files under `path` and print it as JSON or a
 * Mermaid flowchart.
 */
export async function runGraph(argv: readonly string[], io: CliIO): Promise<number> {
  const parsed = parseFlags(argv, [
    { name: 'format', takesValue: true },
    { name: 'output', takesValue: true },
    { name: 'help', takesValue: false, aliases: ['h'] },
  ]);

  if (parsed.bools.has('help')) {
    io.stdout(`${graphHelp()}\n`);
    return EXIT.OK;
  }
  if (parsed.positionals.length > 1) {
    throw new CliUsageError(`graph takes at most one path (got ${parsed.positionals.length})`);
  }

  const rawPath = parsed.positionals[0] ?? '.';
  const target = path.resolve(io.cwd, rawPath);
  const format: GraphFormat = parseFormat(parsed.values.get('format'), GRAPH_FORMATS);
  const outputPath = parsed.values.get('output');

  await assertDirectory(target);

  const discovered = await discoverInfraFiles(target);
  const files: InfraGraphFile[] = await Promise.all(
    discovered.map(async (file) => ({
      relPath: file.relPath,
      text: await readFile(file.absPath, 'utf8'),
    })),
  );

  const graph = buildInfraGraph(files);

  if (graph.nodes.length === 0) {
    io.stderr(`No infrastructure definitions found under ${target}\n`);
  }

  const rendered =
    format === 'json' ? `${JSON.stringify(graph, null, 2)}\n` : renderInfraGraphMermaid(graph);

  if (outputPath !== undefined) {
    const dest = path.resolve(io.cwd, outputPath);
    try {
      await writeFile(dest, rendered, 'utf8');
    } catch (error) {
      io.stderr(
        `error: cannot write ${dest}: ${error instanceof Error ? error.message : String(error)}\n`,
      );
      return EXIT.ERROR;
    }
  } else {
    io.stdout(rendered);
  }

  return EXIT.OK;
}

/** A nonexistent or non-directory target is a usage error (64), not a scan/internal error. */
async function assertDirectory(target: string): Promise<void> {
  let isDirectory: boolean;
  try {
    isDirectory = (await stat(target)).isDirectory();
  } catch (error) {
    throw new CliUsageError(
      `Graph target does not exist: ${target} (${error instanceof Error ? error.message : String(error)})`,
    );
  }
  if (!isDirectory) {
    throw new CliUsageError(`Graph target is not a directory: ${target}`);
  }
}
