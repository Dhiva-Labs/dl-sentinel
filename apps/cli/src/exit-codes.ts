/**
 * Process exit codes, fixed by docs/architecture.md §CLI. CI depends on these.
 *
 * - `OK` (0)     scan ran and policy passed
 * - `POLICY` (1) policy violated (findings at a fail-on severity)
 * - `ERROR` (2)  scan or internal error (including an AbortError)
 * - `USAGE` (64) usage error (bad flags/command/config/report input)
 */
export const EXIT = {
  OK: 0,
  POLICY: 1,
  ERROR: 2,
  USAGE: 64,
} as const;

export type ExitCode = (typeof EXIT)[keyof typeof EXIT];
