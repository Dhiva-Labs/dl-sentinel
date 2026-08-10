import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { ScanLogger, SentinelConfig } from '@dl-sentinel/core';
import { createBaseline } from '@dl-sentinel/core';
import type { ScanOptions } from '@dl-sentinel/engine';
import { loadConfig } from '@dl-sentinel/engine';
import { createDefaultEngine } from '@dl-sentinel/preset';
import { CliUsageError, parseFlags } from '../args.js';
import { makeColors, shouldColor } from '../colors.js';
import { EXIT } from '../exit-codes.js';
import type { CliIO } from '../io.js';
import { parseScannerList } from '../parse.js';
import { createProgressReporter } from '../progress.js';
import { baselineHelp } from '../usage.js';

/** Default baseline filename, written into the scan target directory. */
const DEFAULT_BASELINE_FILE = '.sentinel-baseline.json';

/**
 * `sentinel baseline [path]` — scan the target and write a baseline of the
 * current findings, so a later `scan --baseline <file>` reports only findings
 * introduced afterwards. Exit `0` on success, `2` on a write error, `64` on
 * misuse (bad flags / unusable config).
 */
export async function runBaseline(argv: readonly string[], io: CliIO): Promise<number> {
  const parsed = parseFlags(argv, [
    { name: 'config', takesValue: true },
    { name: 'scanners', takesValue: true },
    { name: 'output', takesValue: true },
    { name: 'quiet', takesValue: false },
    { name: 'no-color', takesValue: false },
    { name: 'help', takesValue: false, aliases: ['h'] },
  ]);

  if (parsed.bools.has('help')) {
    io.stdout(`${baselineHelp()}\n`);
    return EXIT.OK;
  }
  if (parsed.positionals.length > 1) {
    throw new CliUsageError(`baseline takes at most one path (got ${parsed.positionals.length})`);
  }

  const rawPath = parsed.positionals[0] ?? '.';
  const target = path.resolve(io.cwd, rawPath);
  const scanners = parseScannerList(parsed.values.get('scanners'));
  const configFlag = parsed.values.get('config');
  const outputFlag = parsed.values.get('output');
  const quiet = parsed.bools.has('quiet');
  const noColorFlag = parsed.bools.has('no-color');

  // Load config honoring --config; any config problem is a usage error.
  let config: SentinelConfig;
  try {
    const configPath = configFlag === undefined ? undefined : path.resolve(io.cwd, configFlag);
    config = await loadConfig(target, configPath);
  } catch (error) {
    throw new CliUsageError(error instanceof Error ? error.message : String(error));
  }

  // Progress goes to stderr, only when it is a TTY and not suppressed.
  const showProgress = !quiet && io.stderrIsTTY;
  const progress = showProgress
    ? createProgressReporter(
        (line) => io.stderr(`${line}\n`),
        makeColors(shouldColor({ noColorFlag, env: io.env, isTTY: io.stderrIsTTY })),
      )
    : undefined;

  const logger: ScanLogger = {
    debug: () => {},
    info: () => {},
    warn: (message) => io.stderr(`warning: ${message}\n`),
    error: (message) => io.stderr(`error: ${message}\n`),
  };

  const scanOptions: ScanOptions = { target, config, logger };
  if (scanners !== undefined) {
    scanOptions.scanners = scanners;
  }
  if (progress !== undefined) {
    const reporter = progress;
    scanOptions.onEvent = (event) => reporter.onEvent(event);
  }

  const report = await createDefaultEngine().scan(scanOptions);

  const doc = createBaseline(report.findings, {
    target: report.target,
    generatedAt: new Date().toISOString(),
  });

  const dest =
    outputFlag === undefined
      ? path.join(target, DEFAULT_BASELINE_FILE)
      : path.resolve(io.cwd, outputFlag);

  try {
    await writeFile(dest, `${JSON.stringify(doc, null, 2)}\n`, 'utf8');
  } catch (error) {
    io.stderr(
      `error: cannot write ${dest}: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    return EXIT.ERROR;
  }

  if (!quiet) {
    io.stderr(`Wrote baseline with ${doc.count} finding${doc.count === 1 ? '' : 's'} to ${dest}\n`);
  }
  return EXIT.OK;
}
