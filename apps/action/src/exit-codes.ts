/**
 * Process exit codes for the action, mirroring the CLI's convention but with
 * the reduced set a CI check needs:
 *
 * - `OK` (0)     scan ran and no NEW findings hit the fail-on severities
 * - `POLICY` (1) new findings at a fail-on severity (the check fails the PR)
 * - `ERROR` (2)  scan or internal error (bad input, unreadable baseline, …)
 *
 * There is no usage-error code (64): a GitHub Action's inputs come from the
 * workflow, so a bad input is an internal error, not an interactive misuse.
 */
export const EXIT = {
  OK: 0,
  POLICY: 1,
  ERROR: 2,
} as const;

export type ExitCode = (typeof EXIT)[keyof typeof EXIT];
