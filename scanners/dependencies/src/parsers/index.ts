import type { ScanLogger } from '@dl-sentinel/core';
import type { DependencyRecord } from '../types.js';
import { posixBasename } from '../paths.js';
import { errorMessage } from '../util.js';
import { parseCargoLock, parseCargoToml } from './cargo.js';
import { parseGoMod } from './go.js';
import { parsePackageJson, parsePackageLock } from './npm.js';
import { parseRequirementsTxt } from './pip.js';

export { parseCargoLock, parseCargoToml } from './cargo.js';
export { parseGoMod } from './go.js';
export { parsePackageJson, parsePackageLock } from './npm.js';
export { parseRequirementsTxt } from './pip.js';

function isRequirementsFile(base: string): boolean {
  return base === 'requirements.txt' || (base.startsWith('requirements-') && base.endsWith('.txt'));
}

/**
 * Dispatch a discovered file to the right ecosystem parser by basename.
 * Every parser already catches its own parse errors internally (invalid
 * JSON, unrecognized shape) and reports them via `logger.warn`, returning an
 * empty list rather than throwing — this wrapper adds one more layer of
 * defense so a bug in a single parser can never crash the whole scan.
 */
export function parseDependencyFile(
  relPath: string,
  content: string,
  logger: ScanLogger,
): DependencyRecord[] {
  const base = posixBasename(relPath);
  try {
    if (base === 'package.json') return parsePackageJson(relPath, content, logger);
    if (base === 'package-lock.json') return parsePackageLock(relPath, content, logger);
    if (base === 'go.mod') return parseGoMod(relPath, content, logger);
    if (base === 'Cargo.toml') return parseCargoToml(relPath, content, logger);
    if (base === 'Cargo.lock') return parseCargoLock(relPath, content, logger);
    if (isRequirementsFile(base)) return parseRequirementsTxt(relPath, content, logger);
  } catch (error) {
    logger.warn(
      `dependencies: unexpected error parsing ${relPath}, skipping (${errorMessage(error)})`,
    );
    return [];
  }
  return [];
}
