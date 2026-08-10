import { realpathSync, statSync } from 'node:fs';
import path from 'node:path';
import { HttpError } from './http.js';

/**
 * Resolve and validate a requested scan path against the allowlisted scan root.
 *
 * Relative inputs resolve against `scanRoot`; absolute inputs are used as given.
 * The path is then canonicalised with `realpath`, which follows every symlink,
 * so a symlink pointing outside the root resolves to its real (outside) target
 * and is rejected. The final path must be the root itself or a descendant of it.
 *
 * @returns the canonical absolute directory to hand to the engine.
 * @throws {HttpError} 400 for a missing/invalid, non-existent, non-directory, or
 *   out-of-root path.
 */
export function resolveScanTarget(scanRoot: string, input: unknown): string {
  if (typeof input !== 'string' || input.trim() === '') {
    throw new HttpError(
      400,
      'validation_error',
      'Body field "path" is required and must be a non-empty string',
    );
  }
  if (input.includes('\0')) {
    throw new HttpError(400, 'validation_error', 'Scan path contains an invalid character');
  }

  const resolved = path.isAbsolute(input) ? path.resolve(input) : path.resolve(scanRoot, input);

  let real: string;
  try {
    real = realpathSync(resolved);
  } catch {
    throw new HttpError(400, 'validation_error', 'Scan path does not exist or is not accessible');
  }

  const rel = path.relative(scanRoot, real);
  if (rel !== '' && (rel === '..' || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel))) {
    throw new HttpError(
      400,
      'validation_error',
      'Scan path resolves outside the allowed scan root',
    );
  }

  let isDirectory: boolean;
  try {
    isDirectory = statSync(real).isDirectory();
  } catch {
    throw new HttpError(400, 'validation_error', 'Scan path does not exist or is not accessible');
  }
  if (!isDirectory) {
    throw new HttpError(400, 'validation_error', 'Scan path is not a directory');
  }

  return real;
}
