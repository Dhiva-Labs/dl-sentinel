/**
 * @dl-sentinel/cli — library surface of the `sentinel` command line tool.
 *
 * `run(argv, io)` is the whole CLI as a pure-ish function: it takes the argv
 * tokens and an I/O surface and resolves to an exit code. The `main.ts` bin
 * entry is the only side-effectful wrapper (real streams + `process.exit`).
 * Commands and output contract: docs/architecture.md §CLI.
 */
export { run } from './run.js';
export { EXIT } from './exit-codes.js';
export type { ExitCode } from './exit-codes.js';
export type { CliIO } from './io.js';
