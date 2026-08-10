/**
 * Scan lifecycle status helpers, mirrored in public/app.js (which ships as
 * plain browser JS). Kept here as the typechecked, unit-tested source of truth
 * for the status label/class logic the Scans list and scan detail view use.
 */

export type ScanStatus = 'queued' | 'running' | 'completed' | 'failed';

export const SCAN_STATUSES: readonly ScanStatus[] = ['queued', 'running', 'completed', 'failed'];

function isKnown(status: string): status is ScanStatus {
  return (SCAN_STATUSES as readonly string[]).includes(status);
}

/** Human-readable status label, e.g. "running" -> "Running"; unknown -> "Unknown". */
export function scanStatusLabel(status: string): string {
  if (!isKnown(status)) return 'Unknown';
  return status.charAt(0).toUpperCase() + status.slice(1);
}

/** CSS class for a status badge, e.g. `status-running`; unknown -> `status-unknown`. */
export function scanStatusClass(status: string): string {
  return `status-${isKnown(status) ? status : 'unknown'}`;
}

/** A scan is terminal once it has completed or failed (no further transitions). */
export function isTerminalStatus(status: string): boolean {
  return status === 'completed' || status === 'failed';
}
