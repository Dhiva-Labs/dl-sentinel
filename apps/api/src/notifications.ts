import { createHmac } from 'node:crypto';
import type { SeverityStats } from '@dl-sentinel/core';
import { SEVERITY_ORDER } from '@dl-sentinel/core';
import type {
  ChannelType,
  NotificationChannel,
  NotificationEvent,
  NotificationPayload,
  PublicChannel,
} from './types.js';

/**
 * Pure helpers for outbound notifications: validation of a channel record,
 * projection for the wire, payload/summary construction, and body signing.
 * Everything here is side-effect free and network-free — delivery itself lives
 * in `notifier.ts`.
 */

/** Every event a channel may subscribe to, in a stable order. */
export const NOTIFICATION_EVENTS: readonly NotificationEvent[] = [
  'scan.completed',
  'scan.failed',
  'policy.violated',
  'schedule.failed',
];

/** Every supported channel type. */
export const CHANNEL_TYPES: readonly ChannelType[] = ['webhook', 'slack'];

/** How long a single delivery may take before it is aborted. */
export const DELIVERY_TIMEOUT_MS = 5_000;

/** Header carrying the HMAC of the exact request body. */
export const SIGNATURE_HEADER = 'X-Sentinel-Signature';

/**
 * Hosts for which plain `http` is accepted. Everything else must be `https`:
 * a notification body names a project and its severity counts, so it is not
 * something to hand to the network in the clear. A loopback receiver never
 * leaves the machine, so requiring TLS there would only push operators towards
 * self-signed certificates for no gain.
 */
const LOOPBACK_HOSTS: ReadonlySet<string> = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);

/** Caps on caller-supplied strings, so a channel record cannot be bloated. */
export const MAX_CHANNEL_URL_LENGTH = 2048;
export const MAX_CHANNEL_SECRET_LENGTH = 256;
/** Cap on a stored `lastError`, which is derived from a failure, not a body. */
const MAX_LAST_ERROR_LENGTH = 200;

const EVENT_SET: ReadonlySet<string> = new Set(NOTIFICATION_EVENTS);

export function isChannelType(value: unknown): value is ChannelType {
  return value === 'webhook' || value === 'slack';
}

export function isNotificationEvent(value: unknown): value is NotificationEvent {
  return typeof value === 'string' && EVENT_SET.has(value);
}

/** Why a candidate channel field was rejected; `undefined` means it is valid. */
export type ValidationFailure = string | undefined;

/**
 * Validate a delivery URL. It must parse, use `https`, and — as the single
 * exception — may use `http` when the host is loopback (see
 * {@link LOOPBACK_HOSTS}). Returns the reason it was rejected, or `undefined`.
 */
export function checkChannelUrl(value: unknown): ValidationFailure {
  if (typeof value !== 'string' || value.trim() === '') {
    return '"url" is required and must be a non-empty string';
  }
  if (value.length > MAX_CHANNEL_URL_LENGTH) {
    return `"url" must be at most ${MAX_CHANNEL_URL_LENGTH} characters`;
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return '"url" must be a valid absolute URL';
  }
  if (parsed.protocol === 'https:') return undefined;
  if (parsed.protocol === 'http:' && LOOPBACK_HOSTS.has(parsed.hostname)) return undefined;
  return '"url" must use https (plain http is accepted only for localhost/127.0.0.1)';
}

/** True when a URL is acceptable as a channel endpoint. */
export function isValidChannelUrl(value: unknown): boolean {
  return checkChannelUrl(value) === undefined;
}

/**
 * Validate and normalize a subscription list: a non-empty array drawn from
 * {@link NOTIFICATION_EVENTS}, de-duplicated and returned in canonical order so
 * two equivalent requests produce byte-identical records.
 */
export function normalizeEvents(value: unknown): NotificationEvent[] | string {
  if (!Array.isArray(value) || value.length === 0) {
    return `"events" is required and must be a non-empty array of: ${NOTIFICATION_EVENTS.join(', ')}`;
  }
  const unknown = value.filter((entry) => !isNotificationEvent(entry));
  if (unknown.length > 0) {
    return `Unknown event${unknown.length > 1 ? 's' : ''}: ${unknown.map((entry) => String(entry)).join(', ')}`;
  }
  const selected = value as NotificationEvent[];
  return NOTIFICATION_EVENTS.filter((event) => selected.includes(event));
}

/** Validate an optional signing secret. Returns the rejection reason, if any. */
export function checkChannelSecret(value: unknown): ValidationFailure {
  if (typeof value !== 'string' || value === '') {
    return '"secret" must be a non-empty string when present';
  }
  if (value.length > MAX_CHANNEL_SECRET_LENGTH) {
    return `"secret" must be at most ${MAX_CHANNEL_SECRET_LENGTH} characters`;
  }
  return undefined;
}

/**
 * Project a stored channel for the wire. Built field by field on purpose: a
 * spread of {@link NotificationChannel} would carry `secret` into the response,
 * so this is the single place that decides what a channel looks like over HTTP.
 */
export function toPublicChannel(channel: NotificationChannel): PublicChannel {
  const publicChannel: PublicChannel = {
    id: channel.id,
    type: channel.type,
    url: channel.url,
    events: [...channel.events],
    enabled: channel.enabled,
    hasSecret: typeof channel.secret === 'string' && channel.secret !== '',
    createdAt: channel.createdAt,
  };
  if (channel.lastError !== undefined) publicChannel.lastError = channel.lastError;
  return publicChannel;
}

/**
 * Build the payload for a settled scan. Counts and identifiers only — the
 * findings themselves (and therefore any evidence) are deliberately absent.
 */
export function buildPayload(input: {
  event: NotificationPayload['event'];
  scanId: string;
  path: string;
  project: string;
  stats: SeverityStats;
  findingCount: number;
  finishedAt: string;
  scheduleId?: string;
}): NotificationPayload {
  const payload: NotificationPayload = {
    event: input.event,
    scanId: input.scanId,
    path: input.path,
    project: input.project,
    stats: input.stats,
    findingCount: input.findingCount,
    finishedAt: input.finishedAt,
  };
  if (input.scheduleId !== undefined) payload.scheduleId = input.scheduleId;
  return payload;
}

function capitalize(value: string): string {
  return value.length === 0 ? value : value[0]?.toUpperCase() + value.slice(1);
}

/**
 * The Slack incoming-webhook text: event, project, finding count, and the
 * per-severity counts. Nothing else — no evidence, no file contents, and not
 * even the scanned path, which would leak the server's directory layout into a
 * chat room for no diagnostic gain (the id is enough to look the scan up).
 */
export function slackText(payload: NotificationPayload): string {
  const counts = SEVERITY_ORDER.map(
    (severity) => `${capitalize(severity)} ${payload.stats[severity]}`,
  ).join(', ');
  const scheduleSuffix =
    payload.scheduleId === undefined ? '' : ` (schedule ${payload.scheduleId})`;
  return (
    `DL Sentinel: ${payload.event} — ${payload.project}${scheduleSuffix} — ` +
    `${payload.findingCount} finding${payload.findingCount === 1 ? '' : 's'} — ${counts}`
  );
}

/** The exact bytes POSTed to a channel, and (for webhooks) the signed value. */
export function serializeBody(channel: NotificationChannel, payload: NotificationPayload): string {
  return channel.type === 'slack'
    ? JSON.stringify({ text: slackText(payload) })
    : JSON.stringify(payload);
}

/**
 * `sha256=<hex>` HMAC of the exact serialized body. A receiver recomputes this
 * over the raw bytes it read — not over a re-serialization of the parsed JSON,
 * which may reorder keys — and compares in constant time.
 */
export function signBody(secret: string, body: string): string {
  return `sha256=${createHmac('sha256', secret).update(body, 'utf8').digest('hex')}`;
}

/**
 * Reduce a delivery failure to something safe to persist and show an admin: a
 * status line or a short error class/message, truncated. Response bodies are
 * never read (they may echo the request, and with it the signature), and the
 * URL — which can itself embed a Slack token — is never repeated back.
 */
export function sanitizeDeliveryError(error: unknown): string {
  let message: string;
  if (error instanceof Error) {
    // AbortError / TimeoutError from the 5s deadline read clearly on their own.
    message = error.name === 'Error' ? error.message : `${error.name}: ${error.message}`;
  } else {
    message = String(error);
  }
  message = message.replace(/\s+/g, ' ').trim();
  if (message === '') message = 'Delivery failed';
  return message.length > MAX_LAST_ERROR_LENGTH
    ? `${message.slice(0, MAX_LAST_ERROR_LENGTH - 1)}…`
    : message;
}

/** The `lastError` recorded when a receiver answered with a >= 400 status. */
export function statusError(status: number): string {
  return `Receiver responded ${status}`;
}
