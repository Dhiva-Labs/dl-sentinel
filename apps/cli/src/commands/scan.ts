import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { ReportFormat, ScanLogger, SentinelConfig } from '@dl-sentinel/core';
import { evaluatePolicy } from '@dl-sentinel/core';
import type { ScanOptions } from '@dl-sentinel/engine';
import { loadConfig } from '@dl-sentinel/engine';
import { createDefaultEngine } from '@dl-sentinel/preset';
import { renderReport } from '@dl-sentinel/reporting';
import { CliUsageError, parseFlags } from '../args.js';
import { makeColors, shouldColor } from '../colors.js';
import { EXIT } from '../exit-codes.js';
import type { CliIO } from '../io.js';
import { parseFormat, parseScannerList, parseSeverityList } from '../parse.js';
import { createProgressReporter } from '../progress.js';
import { scanHelp } from '../usage.js';

const SCAN_FORMATS: readonly ReportFormat[] = ['terminal', 'json', 'markdown', 'sarif'];

/**
 * `sentinel scan [path]` — load config, run the default engine over the target,
 * render the report, and derive the process exit code from the policy result.
 */
export async function runScan(argv: readonly string[], io: CliIO): Promise<number> {
  const parsed = parseFlags(argv, [
    { name: 'config', takesValue: true },
    { name: 'format', takesValue: true },
    { name: 'output', takesValue: true },
    { name: 'scanners', takesValue: true },
    { name: 'fail-on', takesValue: true },
    { name: 'quiet', takesValue: false },
    { name: 'no-color', takesValue: false },
    { name: 'help', takesValue: false, aliases: ['h'] },
  ]);

  if (parsed.bools.has('help')) {
    io.stdout(`${scanHelp()}\n`);
    return EXIT.OK;
  }

  if (parsed.positionals.length > 1) {
    throw new CliUsageError(`scan takes at most one path (got ${parsed.positionals.length})`);
  }

  const rawPath = parsed.positionals[0] ?? '.';
  const target = path.resolve(io.cwd, rawPath);
  const format = parseFormat(parsed.values.get('format'), SCAN_FORMATS);
  const scanners = parseScannerList(parsed.values.get('scanners'));
  const failOn = parseSeverityList(parsed.values.get('fail-on'), 'fail-on');
  const configFlag = parsed.values.get('config');
  const outputPath = parsed.values.get('output');
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

  // Apply the --fail-on override on top of the loaded policy.
  if (failOn !== undefined) {
    config = { ...config, policy: { ...config.policy, failOn } };
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

  const rendered = renderReport(report, format);
  if (outputPath !== undefined) {
    const dest = path.resolve(io.cwd, outputPath);
    try {
      await writeFile(dest, `${rendered}\n`, 'utf8');
    } catch (error) {
      io.stderr(
        `error: cannot write ${dest}: ${error instanceof Error ? error.message : String(error)}\n`,
      );
      return EXIT.ERROR;
    }
  } else {
    io.stdout(`${rendered}\n`);
  }

  return evaluatePolicy(report.stats, config.policy).pass ? EXIT.OK : EXIT.POLICY;
}
