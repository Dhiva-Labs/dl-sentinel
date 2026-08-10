/**
 * Schedule-view helpers, mirrored in public/app.js. Kept here as the
 * typechecked, unit-tested source of truth for interval formatting so the
 * Schedules view can render a cadence without duplicating fiddly math inline.
 */

/**
 * Format a millisecond interval as a compact human string, e.g. 60000 -> "1m",
 * 5400000 -> "1h 30m", 90000 -> "1m 30s". Non-finite or negative input -> "—".
 */
export function formatInterval(ms: number): string {
  if (!Number.isFinite(ms) || ms < 0) return '—';
  const totalSeconds = Math.round(ms / 1000);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  const parts: string[] = [];
  if (hours > 0) parts.push(`${hours}h`);
  if (minutes > 0) parts.push(`${minutes}m`);
  if (seconds > 0) parts.push(`${seconds}s`);
  return parts.length > 0 ? parts.join(' ') : '0s';
}
