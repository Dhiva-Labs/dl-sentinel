#!/usr/bin/env node
/**
 * Bin entry for `sentinel`. Kept deliberately thin: build the real I/O surface
 * from `process`, delegate to `run()`, then translate its exit code into a
 * `process.exit`. Any escaped rejection (run() itself catches command errors)
 * is reported and mapped to the internal-error exit code.
 */
import process from 'node:process';
import { EXIT } from './exit-codes.js';
import type { CliIO } from './io.js';
import { run } from './run.js';

const io: CliIO = {
  cwd: process.cwd(),
  env: process.env,
  stdout: (text) => {
    process.stdout.write(text);
  },
  stderr: (text) => {
    process.stderr.write(text);
  },
  stdoutIsTTY: process.stdout.isTTY === true,
  stderrIsTTY: process.stderr.isTTY === true,
};

run(process.argv.slice(2), io)
  .then((code) => {
    process.exit(code);
  })
  .catch((error: unknown) => {
    const detail = error instanceof Error ? (error.stack ?? error.message) : String(error);
    process.stderr.write(`fatal: ${detail}\n`);
    process.exit(EXIT.ERROR);
  });
