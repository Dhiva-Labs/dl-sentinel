/**
 * @dl-sentinel/engine — scan orchestration.
 *
 * Loads configuration, discovers files, runs registered scanner plugins
 * concurrently with failure isolation, and aggregates their findings into a
 * `Report`. Scanned code is never executed and file contents are never logged.
 *
 * ```ts
 * const engine = createEngine();
 * engine.register(secretsScanner);
 * const report = await engine.scan({ target: './project' });
 * ```
 *
 * Contract: docs/architecture.md (§@dl-sentinel/engine) and
 * docs/scanner-interface.md.
 */
export { createEngine } from './engine.js';
export type { ScanEngine, ScanOptions } from './engine.js';
export { loadConfig } from './config.js';
