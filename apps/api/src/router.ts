import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Finding, Report, ReportFormat, Severity } from '@dl-sentinel/core';
import { SEVERITY_ORDER } from '@dl-sentinel/core';
import type { ScanEngine } from '@dl-sentinel/engine';
import { BUILTIN_SCANNERS } from '@dl-sentinel/preset';
import { renderReport } from '@dl-sentinel/reporting';
import { HttpError, methodNotAllowed, notFound, readJsonBody, sendJson, sendText } from './http.js';
import { resolveScanTarget } from './scan-path.js';
import type { ReportStore } from './store.js';
import type { ApiRule, ServerLogger, SentinelRuntime } from './types.js';

export interface HandlerContext {
  req: IncomingMessage;
  res: ServerResponse;
  url: URL;
  runtime: SentinelRuntime;
  store: ReportStore;
  engineFactory: () => ScanEngine;
  logger: ServerLogger;
}

const SEVERITIES = new Set<string>(SEVERITY_ORDER);
const SCANNER_IDS = new Set<string>(BUILTIN_SCANNERS.map((scanner) => scanner.id));
const REPORT_FORMATS = new Set<string>(['json', 'markdown', 'sarif']);

function decodeSegment(segment: string): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}

/** All built-in rules, each annotated with its owning scanner id. */
function buildRules(): ApiRule[] {
  const rules: ApiRule[] = [];
  for (const scanner of BUILTIN_SCANNERS) {
    for (const rule of scanner.rules) {
      rules.push({ ...rule, scanner: scanner.id });
    }
  }
  return rules;
}

/** Apply optional ?severity= and ?scanner= filters, validating each value. */
function applyFindingFilters(findings: readonly Finding[], url: URL): Finding[] {
  const severity = url.searchParams.get('severity');
  const scanner = url.searchParams.get('scanner');
  let result = [...findings];
  if (severity !== null) {
    if (!SEVERITIES.has(severity)) {
      throw new HttpError(400, 'validation_error', `Unknown severity filter: ${severity}`);
    }
    result = result.filter((finding) => finding.severity === (severity as Severity));
  }
  if (scanner !== null) {
    if (!SCANNER_IDS.has(scanner)) {
      throw new HttpError(400, 'validation_error', `Unknown scanner filter: ${scanner}`);
    }
    result = result.filter((finding) => finding.scanner === scanner);
  }
  return result;
}

function parseReportFormat(value: string | null): ReportFormat {
  if (value === null || value === '') return 'json';
  if (!REPORT_FORMATS.has(value)) {
    throw new HttpError(
      400,
      'validation_error',
      `Unknown report format: ${value}. Supported: json, markdown, sarif`,
    );
  }
  return value as ReportFormat;
}

function validateScanners(value: unknown): string[] | undefined {
  if (value === undefined || value === null) return undefined;
  if (!Array.isArray(value) || !value.every((entry) => typeof entry === 'string')) {
    throw new HttpError(400, 'validation_error', '"scanners" must be an array of scanner ids');
  }
  const ids = value as string[];
  const unknown = ids.filter((id) => !SCANNER_IDS.has(id));
  if (unknown.length > 0) {
    throw new HttpError(
      400,
      'validation_error',
      `Unknown scanner${unknown.length > 1 ? 's' : ''}: ${unknown.join(', ')}`,
    );
  }
  return ids;
}

async function createScan(ctx: HandlerContext): Promise<void> {
  const body = await readJsonBody(ctx.req, ctx.runtime.maxBodyBytes);
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    throw new HttpError(400, 'validation_error', 'Request body must be a JSON object');
  }
  const record = body as Record<string, unknown>;
  const target = resolveScanTarget(ctx.runtime.scanRoot, record['path']);
  const scanners = validateScanners(record['scanners']);

  let report: Report;
  try {
    const engine = ctx.engineFactory();
    report = await engine.scan(scanners === undefined ? { target } : { target, scanners });
  } catch (error) {
    // The engine flags caller mistakes (unknown scanner, bad target) as
    // UsageError; surface those as 400 rather than a 500.
    if (error instanceof Error && error.name === 'UsageError') {
      throw new HttpError(400, 'validation_error', error.message);
    }
    throw error;
  }

  const stored = ctx.store.create(report);
  sendJson(ctx.res, 201, { id: stored.id, status: stored.status, stats: report.stats });
}

function listScans(ctx: HandlerContext): void {
  sendJson(ctx.res, 200, ctx.store.summaries());
}

function getScan(ctx: HandlerContext, id: string): void {
  const scan = ctx.store.get(id);
  if (scan === undefined) throw notFound('Scan not found');
  sendJson(ctx.res, 200, scan.report);
}

function getScanFindings(ctx: HandlerContext, id: string): void {
  const scan = ctx.store.get(id);
  if (scan === undefined) throw notFound('Scan not found');
  sendJson(ctx.res, 200, applyFindingFilters(scan.report.findings, ctx.url));
}

function getAllFindings(ctx: HandlerContext): void {
  sendJson(ctx.res, 200, applyFindingFilters(ctx.store.allFindings(), ctx.url));
}

function getRules(ctx: HandlerContext): void {
  sendJson(ctx.res, 200, buildRules());
}

function getReport(ctx: HandlerContext, id: string): void {
  const scan = ctx.store.get(id);
  if (scan === undefined) throw notFound('Scan not found');
  const format = parseReportFormat(ctx.url.searchParams.get('format'));
  const rendered = renderReport(scan.report, format);
  const contentType =
    format === 'markdown' ? 'text/markdown; charset=utf-8' : 'application/json; charset=utf-8';
  sendText(ctx.res, 200, rendered, contentType);
}

/**
 * Dispatch an authenticated `/api/*` request. Path parameters are matched by
 * segment; unknown paths are 404 and wrong methods on known paths are 405.
 */
export async function routeApi(ctx: HandlerContext): Promise<void> {
  const method = ctx.req.method ?? 'GET';
  const segments = ctx.url.pathname
    .split('/')
    .filter((segment) => segment.length > 0)
    .map(decodeSegment);
  const rest = segments.slice(1); // drop the leading "api"
  const [first, second, third] = rest;

  if (rest.length === 1 && first === 'scans') {
    if (method === 'GET') return listScans(ctx);
    if (method === 'POST') return createScan(ctx);
    throw methodNotAllowed('GET, POST');
  }
  if (rest.length === 2 && first === 'scans' && second !== undefined) {
    if (method !== 'GET') throw methodNotAllowed('GET');
    return getScan(ctx, second);
  }
  if (rest.length === 3 && first === 'scans' && second !== undefined && third === 'findings') {
    if (method !== 'GET') throw methodNotAllowed('GET');
    return getScanFindings(ctx, second);
  }
  if (rest.length === 1 && first === 'findings') {
    if (method !== 'GET') throw methodNotAllowed('GET');
    return getAllFindings(ctx);
  }
  if (rest.length === 1 && first === 'rules') {
    if (method !== 'GET') throw methodNotAllowed('GET');
    return getRules(ctx);
  }
  if (rest.length === 2 && first === 'reports' && second !== undefined) {
    if (method !== 'GET') throw methodNotAllowed('GET');
    return getReport(ctx, second);
  }
  throw notFound('Unknown API endpoint');
}
