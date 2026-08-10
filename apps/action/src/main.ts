#!/usr/bin/env node
/**
 * Bin entry for the action (declared as `runs.main` in action.yml). Kept thin:
 * build the real I/O surface from `process` and the global `fetch`, delegate to
 * `runAction()`, then translate its exit code into `process.exit`. Any escaped
 * rejection (runAction itself catches its errors) is reported and mapped to the
 * internal-error exit code.
 */
import process from 'node:process';
import { runAction } from './action.js';
import { EXIT } from './exit-codes.js';
import type { ActionIO, FetchInitLike } from './io.js';

const io: ActionIO = {
  env: process.env,
  stdout: (text) => {
    process.stdout.write(text);
  },
  stderr: (text) => {
    process.stderr.write(text);
  },
  fetch: (url: string, init?: FetchInitLike) => fetch(url, init),
};

runAction(io)
  .then((code) => {
    process.exit(code);
  })
  .catch((err: unknown) => {
    const detail = err instanceof Error ? (err.stack ?? err.message) : String(err);
    process.stderr.write(`fatal: ${detail}\n`);
    process.exit(EXIT.ERROR);
  });
