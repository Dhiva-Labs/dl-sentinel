import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import type {
  Baseline,
  Finding,
  Report,
  ReportFormat,
  ScanLogger,
  SentinelConfig,
} from '@dl-sentinel/core';
import {
  applyBaseline,
  computeStats,
  createBaseline,
  evaluatePolicy,
  parseBaseline,
} from '@dl-sentinel/core';
import type { ScanOptions } from '@dl-sentinel/engine';
import { loadConfig } from '@dl-sentinel/engine';
import { renderReport } from '@dl-sentinel/reporting';
import { CliUsageError, parseFlags } from '../args.js';
import { makeColors, shouldColor } from '../colors.js';
import { EXIT } from '../exit-codes.js';
import type { CliIO } from '../io.js';
import { parseFormat, parseScannerList, parseSeverityList } from '../parse.js';
import { PLUGIN_FLAG, engineWithPlugins, loadPlugins, pluginSpecs } from '../plugins.js';
import { createProgressReporter } from '../progress.js';
import { scanHelp } from '../usage.js';

const SCAN_FORMATS: readonly ReportFormat[] = ['terminal', 'json', 'markdown', 'sarif'];

/**
 * `sentinel scan [path]` — load config, run the default engine over the target,
 * render the report, and derive the process exit code from the policy result.
 *
 * Optional baseline handling: `--baseline <file>` narrows the report to findings
 * absent from that baseline (the policy/exit code then reflects NEW findings
 * only); `--write-baseline <file>` records the scan's findings after reporting.
 */
export async function runScan(argv: readonly string[], io: CliIO): Promise<number> {
  const parsed = parseFlags(argv, [
    { name: 'config', takesValue: true },
    { name: 'format', takesValue: true },
    { name: 'output', takesValue: true },
    { name: 'scanners', takesValue: true },
    { name: 'fail-on', takesValue: true },
    { name: 'baseline', takesValue: true },
    { name: 'write-baseline', takesValue: true },
    PLUGIN_FLAG,
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
  // Plugins load before anything else runs, so a bad spec fails fast (64) and
  // `--scanners` can name a plugin's id.
  const plugins = await loadPlugins(pluginSpecs(parsed), io);
  const scanners = parseScannerList(
    parsed.values.get('scanners'),
    plugins.map((entry) => entry.plugin.id),
  );
  const failOn = parseSeverityList(parsed.values.get('fail-on'), 'fail-on');
  const configFlag = parsed.values.get('config');
  const outputPath = parsed.values.get('output');
  const baselineFlag = parsed.values.get('baseline');
  const writeBaselineFlag = parsed.values.get('write-baseline');
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

  // Read the baseline (if any) before scanning, so a bad file fails fast (64).
  const baseline = baselineFlag === undefined ? undefined : await loadBaseline(baselineFlag, io);

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

  const scanned = await engineWithPlugins(plugins).scan(scanOptions);
  // Findings after engine-side suppression. Both --baseline (partition) and
  // --write-baseline (regenerate) operate on this full set, so a run that does
  // both still records every current finding even though it reports only new.
  const scannedFindings = scanned.findings;

  // A baseline narrows the report to NEW findings and records the split; the
  // policy/exit code is then evaluated against those new findings only.
  let report: Report = scanned;
  if (baseline !== undefined) {
    const { newFindings, baselined } = applyBaseline(scannedFindings, baseline);
    report = {
      ...scanned,
      findings: newFindings,
      stats: computeStats(newFindings),
      baseline: { newFindings: newFindings.length, baselined: baselined.length },
    };
  }

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

  // --write-baseline records the current findings after the report is emitted.
  if (writeBaselineFlag !== undefined) {
    const written = await writeBaseline(writeBaselineFlag, scannedFindings, scanned.target, io);
    if (!written) return EXIT.ERROR;
    if (!quiet) {
      const dest = path.resolve(io.cwd, writeBaselineFlag);
      io.stderr(
        `Wrote baseline with ${scannedFindings.length} finding${
          scannedFindings.length === 1 ? '' : 's'
        } to ${dest}\n`,
      );
    }
  }

  return evaluatePolicy(report.stats, config.policy).pass ? EXIT.OK : EXIT.POLICY;
}

/**
 * Read and validate a baseline file. Any problem — unreadable, not JSON, or the
 * wrong shape — is a usage error (64). The file's raw contents are never echoed
 * into the message: a baseline is untrusted input to a security tool.
 */
async function loadBaseline(baselineFlag: string, io: CliIO): Promise<Baseline> {
  const file = path.resolve(io.cwd, baselineFlag);
  let text: string;
  try {
    text = await readFile(file, 'utf8');
  } catch (error) {
    throw new CliUsageError(
      `Cannot read baseline file ${file}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  let data: unknown;
  try {
    data = JSON.parse(text) as unknown;
  } catch {
    // Deliberately omit the parser detail — it can quote bytes from the file.
    throw new CliUsageError(`Baseline file ${file} is not valid JSON`);
  }
  try {
    return parseBaseline(data);
  } catch (error) {
    throw new CliUsageError(
      `Baseline file ${file} is not a valid DL Sentinel baseline: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
}

/** Write a baseline built from `findings`; reports a write failure on stderr. */
async function writeBaseline(
  writeBaselineFlag: string,
  findings: readonly Finding[],
  target: string,
  io: CliIO,
): Promise<boolean> {
  const dest = path.resolve(io.cwd, writeBaselineFlag);
  const doc = createBaseline(findings, { target, generatedAt: new Date().toISOString() });
  try {
    await writeFile(dest, `${JSON.stringify(doc, null, 2)}\n`, 'utf8');
    return true;
  } catch (error) {
    io.stderr(
      `error: cannot write ${dest}: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    return false;
  }
}
