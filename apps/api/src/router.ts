import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Finding, ReportFormat, Severity } from '@dl-sentinel/core';
import { SEVERITY_ORDER } from '@dl-sentinel/core';
import { BUILTIN_SCANNERS } from '@dl-sentinel/preset';
import { renderReport } from '@dl-sentinel/reporting';
import {
  HttpError,
  methodNotAllowed,
  notFound,
  readJsonBody,
  scanNotReady,
  sendJson,
  sendText,
} from './http.js';
import type { ScanQueue } from './queue.js';
import { resolveScanTarget } from './scan-path.js';
import type { ReportStore } from './store.js';
import type { ApiRule, ScanRecord, ServerLogger, SentinelRuntime } from './types.js';

export interface HandlerContext {
  req: IncomingMessage;
  res: ServerResponse;
  url: URL;
  runtime: SentinelRuntime;
  store: ReportStore;
  queue: ScanQueue;
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

/** A scan is servable by report endpoints only once it has completed. */
function requireCompleted(
  scan: ScanRecord,
): asserts scan is ScanRecord & { report: NonNullable<ScanRecord['report']> } {
  if (scan.status !== 'completed' || scan.report === undefined) {
    throw scanNotReady(scan.status);
  }
}

async function createScan(ctx: HandlerContext): Promise<void> {
  const body = await readJsonBody(ctx.req, ctx.runtime.maxBodyBytes);
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    throw new HttpError(400, 'validation_error', 'Request body must be a JSON object');
  }
  const record = body as Record<string, unknown>;
  // Path isolation and scanner validation happen up front, before enqueueing, so
  // an invalid request is rejected synchronously with 400 (never a queued job).
  const target = resolveScanTarget(ctx.runtime.scanRoot, record['path']);
  const scanners = validateScanners(record['scanners']);

  const created = ctx.store.create(
    scanners === undefined ? { path: target } : { path: target, scanners },
  );
  ctx.queue.enqueue(created.id);
  sendJson(ctx.res, 202, { id: created.id, status: created.status });
}

function listScans(ctx: HandlerContext): void {
  sendJson(ctx.res, 200, ctx.store.summaries());
}

function getScan(ctx: HandlerContext, id: string): void {
  const scan = ctx.store.get(id);
  if (scan === undefined) throw notFound('Scan not found');
  // The full record: `report` present iff completed, `error` present iff failed.
  sendJson(ctx.res, 200, scan);
}

function getScanFindings(ctx: HandlerContext, id: string): void {
  const scan = ctx.store.get(id);
  if (scan === undefined) throw notFound('Scan not found');
  requireCompleted(scan);
  sendJson(ctx.res, 200, applyFindingFilters(scan.report.findings, ctx.url));
}

function getAllFindings(ctx: HandlerContext): void {
  // store.allFindings() already aggregates completed scans only.
  sendJson(ctx.res, 200, applyFindingFilters(ctx.store.allFindings(), ctx.url));
}

function getRules(ctx: HandlerContext): void {
  sendJson(ctx.res, 200, buildRules());
}

function getReport(ctx: HandlerContext, id: string): void {
  const scan = ctx.store.get(id);
  if (scan === undefined) throw notFound('Scan not found');
  requireCompleted(scan);
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
