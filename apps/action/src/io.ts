/**
 * The side-effect surface the action needs from its host. `runAction()` takes
 * one of these so tests can drive it in-process — capturing stdout/stderr,
 * setting a fixed env, and injecting a fake `fetch` so nothing touches the
 * network. `main.ts` is the only place that binds these to the real process.
 *
 * File I/O ($GITHUB_OUTPUT, $GITHUB_STEP_SUMMARY, the SARIF file, baseline
 * files) is done directly against `node:fs`; tests point the relevant env vars
 * at paths under `os.tmpdir()`, so it stays hermetic without an fs shim. Only
 * networking is injected, because only networking would otherwise escape.
 */

/** The subset of the WHATWG `Response` the action reads. `fetch`'s real Response satisfies it. */
export interface FetchResponseLike {
  readonly ok: boolean;
  readonly status: number;
  json(): Promise<unknown>;
  text(): Promise<string>;
}

/** The subset of `RequestInit` the action sends. */
export interface FetchInitLike {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
}

/** Injectable `fetch`. The global `fetch` is assignable to this. */
export type FetchLike = (url: string, init?: FetchInitLike) => Promise<FetchResponseLike>;

export interface ActionIO {
  /** Environment the action reads its configuration from (GITHUB_*, INPUT_*). */
  readonly env: NodeJS.ProcessEnv;
  /** Write to standard output verbatim (no newline added). Workflow commands go here. */
  stdout(text: string): void;
  /** Write to standard error verbatim (no newline added). */
  stderr(text: string): void;
  /** Perform an HTTP request. Injected so tests never hit the network. */
  fetch: FetchLike;
}
