import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { Report, ReportFormat } from '@dl-sentinel/core';
import { renderReport } from '@dl-sentinel/reporting';
import { CliUsageError, parseFlags } from '../args.js';
import { EXIT } from '../exit-codes.js';
import type { CliIO } from '../io.js';
import { parseFormat } from '../parse.js';
import { reportHelp } from '../usage.js';

const REPORT_FORMATS: readonly ReportFormat[] = ['terminal', 'json', 'markdown', 'sarif'];

/**
 * `sentinel report <file>` — re-render a saved JSON report in another format.
 * A missing, non-JSON, or non-Report file is treated as a usage error (64).
 */
export async function runReport(argv: readonly string[], io: CliIO): Promise<number> {
  const parsed = parseFlags(argv, [
    { name: 'format', takesValue: true },
    { name: 'output', takesValue: true },
    { name: 'no-color', takesValue: false },
    { name: 'help', takesValue: false, aliases: ['h'] },
  ]);

  if (parsed.bools.has('help')) {
    io.stdout(`${reportHelp()}\n`);
    return EXIT.OK;
  }
  if (parsed.positionals.length === 0) {
    throw new CliUsageError('report requires a <file> argument');
  }
  if (parsed.positionals.length > 1) {
    throw new CliUsageError(
      `report takes exactly one <file> argument (got ${parsed.positionals.length})`,
    );
  }

  const file = path.resolve(io.cwd, parsed.positionals[0] ?? '');
  const format = parseFormat(parsed.values.get('format'), REPORT_FORMATS);
  const outputPath = parsed.values.get('output');

  let text: string;
  try {
    text = await readFile(file, 'utf8');
  } catch (error) {
    throw new CliUsageError(
      `Cannot read report file ${file}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch (error) {
    throw new CliUsageError(
      `Report file ${file} is not valid JSON: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
  if (!isReport(data)) {
    throw new CliUsageError(`Report file ${file} is not a valid DL Sentinel report`);
  }

  const rendered = renderReport(data, format);
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
  return EXIT.OK;
}

/** Structural check that a parsed value matches the `Report` contract. */
function isReport(value: unknown): value is Report {
  if (typeof value !== 'object' || value === null) return false;
  const report = value as Record<string, unknown>;

  const tool = report.tool;
  if (typeof tool !== 'object' || tool === null) return false;
  const toolRecord = tool as Record<string, unknown>;
  if (typeof toolRecord.name !== 'string' || typeof toolRecord.version !== 'string') return false;

  if (typeof report.project !== 'string' || typeof report.target !== 'string') return false;
  if (typeof report.startedAt !== 'string' || typeof report.finishedAt !== 'string') return false;
  if (typeof report.durationMs !== 'number') return false;
  if (!Array.isArray(report.scannersRun)) return false;
  if (!Array.isArray(report.findings)) return false;
  if (!Array.isArray(report.errors)) return false;

  const stats = report.stats;
  if (typeof stats !== 'object' || stats === null) return false;
  const statsRecord = stats as Record<string, unknown>;
  for (const key of ['critical', 'high', 'medium', 'low', 'info'] as const) {
    if (typeof statsRecord[key] !== 'number') return false;
  }
  return true;
}
