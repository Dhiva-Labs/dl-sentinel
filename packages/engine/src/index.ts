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
 * Third-party scanners load through `loadScannerPlugin`, which is reachable
 * only from explicit operator input (the CLI's `--plugin` flag, the API's
 * `SENTINEL_PLUGINS` env) and never from a config file — see docs/plugins.md.
 *
 * Contract: docs/architecture.md (§@dl-sentinel/engine, §Plugins) and
 * docs/scanner-interface.md.
 */
export { createEngine } from './engine.js';
export type { ScanEngine, ScanOptions } from './engine.js';
export { loadConfig } from './config.js';
export {
  loadScannerPlugin,
  loadScannerPlugins,
  resolvePluginSource,
  validateScannerPlugin,
} from './plugins.js';
export type { LoadPluginOptions } from './plugins.js';
