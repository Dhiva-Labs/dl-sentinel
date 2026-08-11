import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Finding, ReportFormat, ScannerPlugin, Severity } from '@dl-sentinel/core';
import { SEVERITY_ORDER } from '@dl-sentinel/core';
import { renderReport } from '@dl-sentinel/reporting';
import { generateUserToken, hashToken } from './auth.js';
import {
  forbidden,
  HttpError,
  methodNotAllowed,
  notFound,
  readJsonBody,
  scanNotReady,
  sendJson,
  sendNoContent,
  sendText,
} from './http.js';
import {
  checkChannelSecret,
  checkChannelUrl,
  isChannelType,
  normalizeEvents,
  toPublicChannel,
} from './notifications.js';
import type { Notifier } from './notifier.js';
import { isUserRole, MAX_USER_NAME_LENGTH, requiredRoleFor, roleAtLeast } from './permissions.js';
import type { ScanQueue } from './queue.js';
import { resolveScanTarget } from './scan-path.js';
import type { ReportStore } from './store.js';
import type {
  ApiRule,
  AuthContext,
  ChannelType,
  HistoryEntry,
  NotificationChannel,
  NotificationEvent,
  PublicUser,
  ScanRecord,
  ScheduleRecord,
  ServerLogger,
  SentinelRuntime,
  TrendPoint,
  UserRecord,
  UserRole,
} from './types.js';

export interface HandlerContext {
  req: IncomingMessage;
  res: ServerResponse;
  url: URL;
  runtime: SentinelRuntime;
  /**
   * The registered scanner roster: the built-ins followed by any plugins loaded
   * from `SENTINEL_PLUGINS` / `ServerOptions.plugins`. `/api/rules` lists these,
   * and `scanners` in request bodies and filters is validated against them, so a
   * plugin is addressable exactly like a built-in.
   */
  scanners: readonly ScannerPlugin[];
  store: ReportStore;
  queue: ScanQueue;
  /** Outbound notification delivery; used by the channel test endpoint. */
  notifier: Notifier;
  logger: ServerLogger;
  /** The authenticated caller, resolved by the server before routing. */
  auth: AuthContext;
  /** Injected clock, shared with the scheduler; drives `nextRunAt` arithmetic. */
  now: () => number;
}

/**
 * Smallest interval a schedule may specify. A tighter cadence would let a
 * caller turn the scheduler into a scan-flood generator, so it is rejected.
 */
export const MIN_SCHEDULE_INTERVAL_MS = 60_000;

const SEVERITIES = new Set<string>(SEVERITY_ORDER);
const REPORT_FORMATS = new Set<string>(['json', 'markdown', 'sarif']);

/** Ids of every registered scanner, built-in or plugin. */
function scannerIds(scanners: readonly ScannerPlugin[]): Set<string> {
  return new Set(scanners.map((scanner) => scanner.id));
}

function decodeSegment(segment: string): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}

/** Every registered scanner's rules, each annotated with its owning scanner id. */
function buildRules(scanners: readonly ScannerPlugin[]): ApiRule[] {
  const rules: ApiRule[] = [];
  for (const scanner of scanners) {
    for (const rule of scanner.rules) {
      rules.push({ ...rule, scanner: scanner.id });
    }
  }
  return rules;
}

/** Apply optional ?severity= and ?scanner= filters, validating each value. */
function applyFindingFilters(
  findings: readonly Finding[],
  url: URL,
  scanners: readonly ScannerPlugin[],
): Finding[] {
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
    if (!scannerIds(scanners).has(scanner)) {
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

function validateScanners(
  value: unknown,
  scanners: readonly ScannerPlugin[],
): string[] | undefined {
  if (value === undefined || value === null) return undefined;
  if (!Array.isArray(value) || !value.every((entry) => typeof entry === 'string')) {
    throw new HttpError(400, 'validation_error', '"scanners" must be an array of scanner ids');
  }
  const ids = value as string[];
  const known = scannerIds(scanners);
  const unknown = ids.filter((id) => !known.has(id));
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
  const scanners = validateScanners(record['scanners'], ctx.scanners);

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
  sendJson(ctx.res, 200, applyFindingFilters(scan.report.findings, ctx.url, ctx.scanners));
}

function getAllFindings(ctx: HandlerContext): void {
  // store.allFindings() already aggregates completed scans only.
  sendJson(ctx.res, 200, applyFindingFilters(ctx.store.allFindings(), ctx.url, ctx.scanners));
}

function getRules(ctx: HandlerContext): void {
  sendJson(ctx.res, 200, buildRules(ctx.scanners));
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

/** Validate an interval: a finite number, integer, at or above the minimum. */
function validateInterval(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new HttpError(400, 'validation_error', '"intervalMs" is required and must be a number');
  }
  const ms = Math.trunc(value);
  if (ms < MIN_SCHEDULE_INTERVAL_MS) {
    throw new HttpError(
      400,
      'validation_error',
      `"intervalMs" must be at least ${MIN_SCHEDULE_INTERVAL_MS} (60 seconds)`,
    );
  }
  return ms;
}

/** Parse an optional ?limit= into a positive integer; reject anything else. */
function parseLimit(value: string | null): number | undefined {
  if (value === null || value === '') return undefined;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new HttpError(400, 'validation_error', '"limit" must be a positive integer');
  }
  return parsed;
}

async function createSchedule(ctx: HandlerContext): Promise<void> {
  const body = await readJsonBody(ctx.req, ctx.runtime.maxBodyBytes);
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    throw new HttpError(400, 'validation_error', 'Request body must be a JSON object');
  }
  const record = body as Record<string, unknown>;
  // Same isolation and scanner checks as an ad-hoc scan, up front.
  const target = resolveScanTarget(ctx.runtime.scanRoot, record['path']);
  const scanners = validateScanners(record['scanners'], ctx.scanners);
  const intervalMs = validateInterval(record['intervalMs']);

  const nextRunAt = new Date(ctx.now() + intervalMs).toISOString();
  const created = ctx.store.createSchedule({
    path: target,
    intervalMs,
    nextRunAt,
    ...(scanners === undefined ? {} : { scanners }),
  });
  sendJson(ctx.res, 201, created);
}

function listSchedules(ctx: HandlerContext): void {
  sendJson(ctx.res, 200, ctx.store.listSchedules());
}

function getScheduleById(ctx: HandlerContext, id: string): void {
  const schedule = ctx.store.getSchedule(id);
  if (schedule === undefined) throw notFound('Schedule not found');
  sendJson(ctx.res, 200, schedule);
}

function deleteScheduleById(ctx: HandlerContext, id: string): void {
  if (!ctx.store.deleteSchedule(id)) throw notFound('Schedule not found');
  sendNoContent(ctx.res);
}

async function patchSchedule(ctx: HandlerContext, id: string): Promise<void> {
  const existing = ctx.store.getSchedule(id);
  if (existing === undefined) throw notFound('Schedule not found');

  const body = await readJsonBody(ctx.req, ctx.runtime.maxBodyBytes);
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    throw new HttpError(400, 'validation_error', 'Request body must be a JSON object');
  }
  const patch = body as Record<string, unknown>;

  const updated: ScheduleRecord = { ...existing };
  if (patch['enabled'] !== undefined) {
    if (typeof patch['enabled'] !== 'boolean') {
      throw new HttpError(400, 'validation_error', '"enabled" must be a boolean');
    }
    updated.enabled = patch['enabled'];
  }
  if (patch['intervalMs'] !== undefined) {
    const intervalMs = validateInterval(patch['intervalMs']);
    updated.intervalMs = intervalMs;
    // A changed cadence takes effect from now, not from the old schedule.
    updated.nextRunAt = new Date(ctx.now() + intervalMs).toISOString();
  }
  ctx.store.updateSchedule(updated);
  sendJson(ctx.res, 200, updated);
}

function toHistoryEntry(scan: ScanRecord): HistoryEntry {
  const stats = scan.report?.stats ?? { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  return {
    id: scan.id,
    path: scan.path,
    project: scan.report?.project ?? '',
    finishedAt: scan.finishedAt ?? scan.createdAt,
    stats,
    findingCount: scan.report?.findings.length ?? 0,
  };
}

function toTrendPoint(scan: ScanRecord): TrendPoint {
  const stats = scan.report?.stats ?? { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  return {
    finishedAt: scan.finishedAt ?? scan.createdAt,
    critical: stats.critical,
    high: stats.high,
    medium: stats.medium,
    low: stats.low,
    info: stats.info,
    total: stats.critical + stats.high + stats.medium + stats.low + stats.info,
  };
}

// ---------------------------------------------------------------------------
// Users (admin only) and /api/me
// ---------------------------------------------------------------------------

/**
 * Project a stored user for the wire. Built field by field on purpose: a spread
 * of {@link UserRecord} would carry `tokenHash` into the response, so this is
 * the single place that decides what a user looks like over HTTP.
 */
function toPublicUser(user: UserRecord): PublicUser {
  return {
    id: user.id,
    name: user.name,
    role: user.role,
    createdAt: user.createdAt,
    disabled: user.disabled === true,
  };
}

function requireJsonObject(body: unknown): Record<string, unknown> {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    throw new HttpError(400, 'validation_error', 'Request body must be a JSON object');
  }
  return body as Record<string, unknown>;
}

function validateUserName(value: unknown): string {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new HttpError(
      400,
      'validation_error',
      'Body field "name" is required and must be a non-empty string',
    );
  }
  const name = value.trim();
  if (name.length > MAX_USER_NAME_LENGTH) {
    throw new HttpError(
      400,
      'validation_error',
      `"name" must be at most ${MAX_USER_NAME_LENGTH} characters`,
    );
  }
  return name;
}

function validateRole(value: unknown): UserRole {
  if (!isUserRole(value)) {
    throw new HttpError(
      400,
      'validation_error',
      '"role" is required and must be one of: admin, operator, viewer',
    );
  }
  return value;
}

/** Look a user up by id, or 404. Root is not a record, so `/root` 404s here. */
function requireUser(ctx: HandlerContext, id: string): UserRecord {
  const user = ctx.store.getUser(id);
  if (user === undefined) throw notFound('User not found');
  return user;
}

/**
 * Create a user. The generated token is returned here and **only** here (plus
 * the matching rotate response) — the server keeps just its SHA-256 hash, so it
 * cannot be shown again even to an admin.
 */
async function createUser(ctx: HandlerContext): Promise<void> {
  const record = requireJsonObject(await readJsonBody(ctx.req, ctx.runtime.maxBodyBytes));
  const name = validateUserName(record['name']);
  const role = validateRole(record['role']);

  const token = generateUserToken();
  const created = ctx.store.createUser({ name, role, tokenHash: hashToken(token) });
  sendJson(ctx.res, 201, {
    id: created.id,
    name: created.name,
    role: created.role,
    createdAt: created.createdAt,
    token,
  });
}

function listUsers(ctx: HandlerContext): void {
  sendJson(ctx.res, 200, ctx.store.listUsers().map(toPublicUser));
}

function getUserById(ctx: HandlerContext, id: string): void {
  sendJson(ctx.res, 200, toPublicUser(requireUser(ctx, id)));
}

/** Change a user's role and/or disable them. A disabled user's token 401s. */
async function patchUser(ctx: HandlerContext, id: string): Promise<void> {
  const existing = requireUser(ctx, id);
  const patch = requireJsonObject(await readJsonBody(ctx.req, ctx.runtime.maxBodyBytes));

  const updated: UserRecord = { ...existing };
  if (patch['role'] !== undefined) updated.role = validateRole(patch['role']);
  if (patch['disabled'] !== undefined) {
    if (typeof patch['disabled'] !== 'boolean') {
      throw new HttpError(400, 'validation_error', '"disabled" must be a boolean');
    }
    updated.disabled = patch['disabled'];
  }
  ctx.store.updateUser(updated);
  sendJson(ctx.res, 200, toPublicUser(updated));
}

function deleteUserById(ctx: HandlerContext, id: string): void {
  if (!ctx.store.deleteUser(id)) throw notFound('User not found');
  sendNoContent(ctx.res);
}

/**
 * Issue a fresh token for a user. The stored hash is replaced, so the previous
 * token stops authenticating the moment this returns; the new one is shown once.
 */
function rotateUserToken(ctx: HandlerContext, id: string): void {
  const existing = requireUser(ctx, id);
  const token = generateUserToken();
  ctx.store.updateUser({ ...existing, tokenHash: hashToken(token) });
  sendJson(ctx.res, 200, { token });
}

/** The calling identity, for any valid token. The dashboard role-gates on this. */
function getMe(ctx: HandlerContext): void {
  sendJson(ctx.res, 200, { name: ctx.auth.name, role: ctx.auth.role });
}

// ---------------------------------------------------------------------------
// Notification channels (admin only)
// ---------------------------------------------------------------------------

/** Reject a bad channel field with the shared 400 envelope. */
function rejectIf(reason: string | undefined): void {
  if (reason !== undefined) throw new HttpError(400, 'validation_error', reason);
}

function validateChannelType(value: unknown): ChannelType {
  if (!isChannelType(value)) {
    throw new HttpError(400, 'validation_error', '"type" is required and must be webhook or slack');
  }
  return value;
}

function validateChannelEvents(value: unknown): NotificationEvent[] {
  const normalized = normalizeEvents(value);
  if (typeof normalized === 'string') {
    throw new HttpError(400, 'validation_error', normalized);
  }
  return normalized;
}

/** Look a channel up by id, or 404. */
function requireChannel(ctx: HandlerContext, id: string): NotificationChannel {
  const channel = ctx.store.getChannel(id);
  if (channel === undefined) throw notFound('Notification channel not found');
  return channel;
}

/**
 * Create a channel. The `secret` is accepted here and never echoed: unlike a
 * user token it must be *kept* (it signs webhook bodies), but it is stored only,
 * and every response — this one included — goes through `toPublicChannel`.
 */
async function createChannel(ctx: HandlerContext): Promise<void> {
  const record = requireJsonObject(await readJsonBody(ctx.req, ctx.runtime.maxBodyBytes));
  const type = validateChannelType(record['type']);
  rejectIf(checkChannelUrl(record['url']));
  const events = validateChannelEvents(record['events']);
  if (record['secret'] !== undefined) rejectIf(checkChannelSecret(record['secret']));
  if (record['enabled'] !== undefined && typeof record['enabled'] !== 'boolean') {
    throw new HttpError(400, 'validation_error', '"enabled" must be a boolean');
  }

  const created = ctx.store.createChannel({
    type,
    url: record['url'] as string,
    events,
    ...(typeof record['enabled'] === 'boolean' ? { enabled: record['enabled'] } : {}),
    ...(record['secret'] === undefined ? {} : { secret: record['secret'] as string }),
  });
  sendJson(ctx.res, 201, toPublicChannel(created));
}

function listChannels(ctx: HandlerContext): void {
  sendJson(ctx.res, 200, ctx.store.listChannels().map(toPublicChannel));
}

function getChannelById(ctx: HandlerContext, id: string): void {
  sendJson(ctx.res, 200, toPublicChannel(requireChannel(ctx, id)));
}

/**
 * Update a channel. A supplied `secret` replaces the stored one; `null` removes
 * it (so signing can be turned off without deleting the channel). Omitting the
 * field leaves the existing secret untouched — the API cannot show it back, so
 * a round-trip of a GET response must not silently erase it.
 */
async function patchChannel(ctx: HandlerContext, id: string): Promise<void> {
  const existing = requireChannel(ctx, id);
  const patch = requireJsonObject(await readJsonBody(ctx.req, ctx.runtime.maxBodyBytes));

  const updated: NotificationChannel = { ...existing };
  if (patch['enabled'] !== undefined) {
    if (typeof patch['enabled'] !== 'boolean') {
      throw new HttpError(400, 'validation_error', '"enabled" must be a boolean');
    }
    updated.enabled = patch['enabled'];
  }
  if (patch['url'] !== undefined) {
    rejectIf(checkChannelUrl(patch['url']));
    updated.url = patch['url'] as string;
  }
  if (patch['events'] !== undefined) {
    updated.events = validateChannelEvents(patch['events']);
  }
  if (patch['secret'] !== undefined) {
    if (patch['secret'] === null) delete updated.secret;
    else {
      rejectIf(checkChannelSecret(patch['secret']));
      updated.secret = patch['secret'] as string;
    }
  }
  ctx.store.updateChannel(updated);
  sendJson(ctx.res, 200, toPublicChannel(updated));
}

function deleteChannelById(ctx: HandlerContext, id: string): void {
  if (!ctx.store.deleteChannel(id)) throw notFound('Notification channel not found');
  sendNoContent(ctx.res);
}

/**
 * Send a `test` event through the real delivery path — same serialization, same
 * signature, same injected fetch and 5 s deadline — and report what happened.
 * This is the admin's connectivity check, so a failure here is a `200` carrying
 * `{ ok: false }`, not an HTTP error: the request itself succeeded, it is the
 * receiver that did not answer.
 */
async function testChannel(ctx: HandlerContext, id: string): Promise<void> {
  const result = await ctx.notifier.sendTest(requireChannel(ctx, id));
  sendJson(ctx.res, 200, result);
}

function getHistory(ctx: HandlerContext): void {
  const target = ctx.url.searchParams.get('target') ?? undefined;
  const limit = parseLimit(ctx.url.searchParams.get('limit'));
  let scans = ctx.store.completedScans(target);
  // completedScans() is oldest-first; a limit keeps the most recent N in that
  // same chronological order.
  if (limit !== undefined && scans.length > limit) scans = scans.slice(scans.length - limit);
  sendJson(ctx.res, 200, scans.map(toHistoryEntry));
}

function getTrends(ctx: HandlerContext): void {
  const target = ctx.url.searchParams.get('target') ?? undefined;
  sendJson(ctx.res, 200, ctx.store.completedScans(target).map(toTrendPoint));
}

/**
 * Dispatch an authenticated `/api/*` request. The caller's role is checked
 * first, against the matrix in `permissions.ts` — an under-privileged caller
 * gets `403 { error: { code: "forbidden" } }` before any handler runs, so no
 * work happens (and nothing is disclosed) on a request they may not make.
 * Path parameters are then matched by segment; unknown paths are 404 and wrong
 * methods on known paths are 405.
 */
export async function routeApi(ctx: HandlerContext): Promise<void> {
  const method = ctx.req.method ?? 'GET';
  const segments = ctx.url.pathname
    .split('/')
    .filter((segment) => segment.length > 0)
    .map(decodeSegment);
  const rest = segments.slice(1); // drop the leading "api"
  const [first, second, third] = rest;

  const required = requiredRoleFor(method, rest);
  if (!roleAtLeast(ctx.auth.role, required)) throw forbidden(required);

  if (rest.length === 1 && first === 'me') {
    if (method !== 'GET') throw methodNotAllowed('GET');
    return getMe(ctx);
  }
  if (rest.length === 1 && first === 'users') {
    if (method === 'GET') return listUsers(ctx);
    if (method === 'POST') return createUser(ctx);
    throw methodNotAllowed('GET, POST');
  }
  if (rest.length === 2 && first === 'users' && second !== undefined) {
    if (method === 'GET') return getUserById(ctx, second);
    if (method === 'PATCH') return patchUser(ctx, second);
    if (method === 'DELETE') return deleteUserById(ctx, second);
    throw methodNotAllowed('GET, PATCH, DELETE');
  }
  if (rest.length === 3 && first === 'users' && second !== undefined && third === 'rotate') {
    if (method !== 'POST') throw methodNotAllowed('POST');
    return rotateUserToken(ctx, second);
  }
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
  if (rest.length === 1 && first === 'schedules') {
    if (method === 'GET') return listSchedules(ctx);
    if (method === 'POST') return createSchedule(ctx);
    throw methodNotAllowed('GET, POST');
  }
  if (rest.length === 2 && first === 'schedules' && second !== undefined) {
    if (method === 'GET') return getScheduleById(ctx, second);
    if (method === 'PATCH') return patchSchedule(ctx, second);
    if (method === 'DELETE') return deleteScheduleById(ctx, second);
    throw methodNotAllowed('GET, PATCH, DELETE');
  }
  if (rest.length === 1 && first === 'notifications') {
    if (method === 'GET') return listChannels(ctx);
    if (method === 'POST') return createChannel(ctx);
    throw methodNotAllowed('GET, POST');
  }
  if (rest.length === 2 && first === 'notifications' && second !== undefined) {
    if (method === 'GET') return getChannelById(ctx, second);
    if (method === 'PATCH') return patchChannel(ctx, second);
    if (method === 'DELETE') return deleteChannelById(ctx, second);
    throw methodNotAllowed('GET, PATCH, DELETE');
  }
  if (rest.length === 3 && first === 'notifications' && second !== undefined && third === 'test') {
    if (method !== 'POST') throw methodNotAllowed('POST');
    return testChannel(ctx, second);
  }
  if (rest.length === 1 && first === 'history') {
    if (method !== 'GET') throw methodNotAllowed('GET');
    return getHistory(ctx);
  }
  if (rest.length === 1 && first === 'trends') {
    if (method !== 'GET') throw methodNotAllowed('GET');
    return getTrends(ctx);
  }
  throw notFound('Unknown API endpoint');
}
