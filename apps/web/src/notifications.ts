/**
 * Notifications-view helpers, mirrored in public/app.js. Kept here as the
 * typechecked, unit-tested source of truth for channel formatting and the
 * dashboard's copy of the URL rule the API enforces.
 *
 * As with the rest of this package, the mirror decides only what the UI
 * *offers*: the API validates every field again and answers `400` regardless of
 * what the form let through, so validating here is a courtesy that saves a
 * round-trip, never the boundary.
 */

export type ChannelType = 'webhook' | 'slack';

export type NotificationEvent =
  'scan.completed' | 'scan.failed' | 'policy.violated' | 'schedule.failed';

/** Every event a channel may subscribe to, in the order the form lists them. */
export const NOTIFICATION_EVENTS: readonly NotificationEvent[] = [
  'scan.completed',
  'scan.failed',
  'policy.violated',
  'schedule.failed',
];

/** Reader-facing description of each event, shown beside its checkbox. */
export const EVENT_LABELS: Readonly<Record<NotificationEvent, string>> = {
  'scan.completed': 'Scan completed',
  'scan.failed': 'Scan failed',
  'policy.violated': 'Policy violated',
  'schedule.failed': 'Schedule failed',
};

/**
 * Hosts for which the API accepts plain `http`. Mirrors LOOPBACK_HOSTS in
 * apps/api/src/notifications.ts — everything else must be `https`.
 */
const LOOPBACK_HOSTS: ReadonlySet<string> = new Set(['localhost', '127.0.0.1', '::1', '[::1]']);

export function isChannelType(value: unknown): value is ChannelType {
  return value === 'webhook' || value === 'slack';
}

export function isNotificationEvent(value: unknown): value is NotificationEvent {
  return (
    value === 'scan.completed' ||
    value === 'scan.failed' ||
    value === 'policy.violated' ||
    value === 'schedule.failed'
  );
}

/** Human label for a channel type; anything unrecognised reads as "Unknown". */
export function channelTypeLabel(type: unknown): string {
  if (type === 'webhook') return 'Webhook';
  if (type === 'slack') return 'Slack';
  return 'Unknown';
}

/** Human label for one event; an unknown value is shown verbatim, not dropped. */
export function eventLabel(event: unknown): string {
  return isNotificationEvent(event) ? EVENT_LABELS[event] : String(event ?? '');
}

/**
 * Comma-joined labels for a subscription list. A missing or empty list reads as
 * a dash rather than an empty cell, and an unrecognised entry (a server newer
 * than this dashboard) still shows, so the reader is never told a channel
 * listens to nothing when it does.
 */
export function eventsLabel(events: unknown): string {
  if (!Array.isArray(events) || events.length === 0) return '—';
  return events.map((event) => eventLabel(event)).join(', ');
}

/**
 * The dashboard's copy of the API's URL rule: an absolute URL that is `https`,
 * or `http` only for a loopback host. Kept in sync with `checkChannelUrl` in
 * apps/api/src/notifications.ts.
 */
export function isValidChannelUrl(value: unknown): boolean {
  if (typeof value !== 'string' || value.trim() === '') return false;
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return false;
  }
  if (parsed.protocol === 'https:') return true;
  if (parsed.protocol === 'http:') return LOOPBACK_HOSTS.has(parsed.hostname);
  return false;
}

/** A channel as it arrives from `GET /api/notifications` — all fields untrusted. */
export interface ChannelLike {
  id?: unknown;
  type?: unknown;
  url?: unknown;
  events?: unknown;
  enabled?: unknown;
  hasSecret?: unknown;
  createdAt?: unknown;
  lastError?: unknown;
}

/** One row of the Notifications table, reduced to displayable strings. */
export interface ChannelRow {
  id: string;
  type: string;
  typeLabel: string;
  url: string;
  events: string;
  enabled: boolean;
  status: string;
  hasSecret: boolean;
  /** Raw ISO timestamp; the view formats it for the reader's locale. */
  createdAt: string;
  /** Empty when the last delivery succeeded (or none has been attempted). */
  lastError: string;
}

/**
 * Normalize a channel record for display. Missing or wrongly typed fields
 * degrade to a dash rather than rendering `undefined`, and the values stay raw
 * strings — the view writes them with `textContent`, so nothing is escaped or
 * stripped here (a URL or an error message containing markup must survive
 * intact, and render inert).
 */
export function formatChannelRow(channel: ChannelLike): ChannelRow {
  const enabled = channel.enabled !== false;
  return {
    id: typeof channel.id === 'string' ? channel.id : '',
    type: isChannelType(channel.type) ? channel.type : '',
    typeLabel: channelTypeLabel(channel.type),
    url: typeof channel.url === 'string' && channel.url !== '' ? channel.url : '—',
    events: eventsLabel(channel.events),
    enabled,
    status: enabled ? 'Enabled' : 'Disabled',
    hasSecret: channel.hasSecret === true,
    createdAt: typeof channel.createdAt === 'string' ? channel.createdAt : '',
    lastError: typeof channel.lastError === 'string' ? channel.lastError : '',
  };
}
