import { TOOL_NAME, TOOL_VERSION } from '@dl-sentinel/core';
import { EXIT } from './exit-codes.js';
import type { CliIO } from './io.js';
import { runBaseline } from './commands/baseline.js';
import { runPlugins } from './commands/plugins.js';
import { runReport } from './commands/report.js';
import { runRules } from './commands/rules.js';
import { runScan } from './commands/scan.js';
import { runVersion } from './commands/version.js';
import { topLevelHelp } from './usage.js';

/**
 * Parse `argv` (the tokens after the binary name), run the matching command,
 * and resolve to a process exit code. All output is routed through `io`, so
 * tests drive this in-process; `main.ts` is the only place that touches the
 * real streams and calls `process.exit`.
 *
 * Exit codes (docs/architecture.md §CLI): 0 ok · 1 policy violated · 2 error ·
 * 64 usage error. Reports go to stdout; progress and errors go to stderr, so
 * `--format json` stdout stays machine-parseable.
 */
export async function run(argv: readonly string[], io: CliIO): Promise<number> {
  try {
    return await dispatch(argv, io);
  } catch (error) {
    return handleError(error, io);
  }
}

async function dispatch(argv: readonly string[], io: CliIO): Promise<number> {
  const first = argv[0];
  const rest = argv.slice(1);

  if (first === undefined) {
    // No command: usage to stderr, usage exit code.
    io.stderr(`${topLevelHelp()}\n`);
    return EXIT.USAGE;
  }
  if (first === '--help' || first === '-h') {
    io.stdout(`${topLevelHelp()}\n`);
    return EXIT.OK;
  }
  if (first === '--version' || first === '-V') {
    io.stdout(`${TOOL_NAME} ${TOOL_VERSION}\n`);
    return EXIT.OK;
  }

  switch (first) {
    case 'scan':
      return runScan(rest, io);
    case 'baseline':
      return runBaseline(rest, io);
    case 'rules':
      return runRules(rest, io);
    case 'plugins':
      return runPlugins(rest, io);
    case 'report':
      return runReport(rest, io);
    case 'version':
      return runVersion(rest, io);
    default:
      io.stderr(`Unknown command: ${first}\n\n${topLevelHelp()}\n`);
      return EXIT.USAGE;
  }
}

/** Map a thrown error to an exit code, using the engine's name conventions. */
function handleError(error: unknown, io: CliIO): number {
  const name =
    typeof error === 'object' && error !== null ? (error as { name?: unknown }).name : undefined;
  const message = error instanceof Error ? error.message : String(error);
  if (name === 'UsageError') {
    io.stderr(`error: ${message}\n`);
    return EXIT.USAGE;
  }
  if (name === 'AbortError') {
    io.stderr(`aborted: ${message}\n`);
    return EXIT.ERROR;
  }
  io.stderr(`error: ${message}\n`);
  return EXIT.ERROR;
}
