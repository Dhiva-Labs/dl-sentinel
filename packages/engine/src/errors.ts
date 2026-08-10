/**
 * Internal error helpers shared by the engine modules.
 *
 * Two error shapes leave the engine with a recognisable `name`:
 * - `AbortError` — the scan was cancelled through `ScanOptions.signal`.
 * - `UsageError` — the caller passed something impossible (bad target,
 *   unknown scanner id, duplicate registration). Apps map this to their
 *   usage exit code.
 */

/** Cancellation error. Its `name` is always `'AbortError'`, whatever the abort reason was. */
export function abortError(reason?: unknown): Error {
  const error =
    reason === undefined ? new Error('Scan aborted') : new Error('Scan aborted', { cause: reason });
  error.name = 'AbortError';
  return error;
}

/** Throw an `AbortError` if the signal is already aborted. */
export function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted === true) throw abortError(signal.reason);
}

/** True for the cancellation error shape produced by {@link abortError}. */
export function isAbortError(error: unknown): boolean {
  return error instanceof Error && error.name === 'AbortError';
}

/** Caller mistake rather than a scan failure. */
export function usageError(message: string): Error {
  const error = new Error(message);
  error.name = 'UsageError';
  return error;
}

/**
 * Best-effort message for an unknown thrown value. Non-Error values are
 * stringified rather than serialised, so a scanner that throws a payload
 * cannot smuggle file contents into a report or log line.
 */
export function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === 'string') return error;
  return String(error);
}

/** Stack of a thrown Error, when there is one. */
export function errorStack(error: unknown): string | undefined {
  return error instanceof Error ? error.stack : undefined;
}
