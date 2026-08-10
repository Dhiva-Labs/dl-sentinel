/**
 * The side-effect surface the CLI needs from its host. `run()` takes one of
 * these so tests can drive every command in-process — capturing stdout/stderr
 * into buffers and setting a fixed cwd/env — without spawning a subprocess or
 * touching the real streams.
 */
export interface CliIO {
  /** Directory that relative path arguments resolve against. */
  readonly cwd: string;
  /** Environment (read for NO_COLOR). */
  readonly env: NodeJS.ProcessEnv;
  /** Write a chunk to standard output verbatim (no newline is added). */
  stdout(text: string): void;
  /** Write a chunk to standard error verbatim (no newline is added). */
  stderr(text: string): void;
  /** Whether stdout is a TTY — gates color on report/table output. */
  readonly stdoutIsTTY: boolean;
  /** Whether stderr is a TTY — gates progress rendering. */
  readonly stderrIsTTY: boolean;
}
