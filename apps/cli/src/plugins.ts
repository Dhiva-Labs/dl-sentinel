/**
 * `--plugin` handling shared by `scan`, `rules`, `baseline` and `plugins`.
 *
 * The flag is the *only* way the CLI loads third-party scanners: a plugin is
 * operator-chosen executable code, and configuration — which can live inside the
 * repository being scanned — must never be able to decide what gets imported
 * (docs/plugins.md). Anything that goes wrong while loading or registering is a
 * {@link CliUsageError}, so a mistyped spec, a malformed plugin, or an id that
 * collides with a built-in exits 64 with the loader's own message, before any
 * scanning begins.
 */
import type { ScannerPlugin } from '@dl-sentinel/core';
import type { ScanEngine } from '@dl-sentinel/engine';
import { loadScannerPlugins, resolvePluginSource } from '@dl-sentinel/engine';
import { BUILTIN_SCANNERS, createDefaultEngine } from '@dl-sentinel/preset';
import { CliUsageError, repeated } from './args.js';
import type { ParsedFlags } from './args.js';
import type { CliIO } from './io.js';

/** The flag spec every command that accepts plugins declares. */
export const PLUGIN_FLAG = { name: 'plugin', takesValue: true } as const;

/** A loaded plugin together with where it came from, for listings and errors. */
export interface LoadedPlugin {
  /** The `--plugin` value exactly as the operator typed it. */
  spec: string;
  /** Absolute file path, or the package specifier when it is a bare one. */
  source: string;
  plugin: ScannerPlugin;
}

/** The `--plugin` values of a parsed command line, in the order given. */
export function pluginSpecs(parsed: ParsedFlags): string[] {
  return repeated(parsed, PLUGIN_FLAG.name);
}

/**
 * Load every `--plugin` spec, relative to the CLI's cwd. Order is preserved:
 * plugins are registered after the built-ins, in flag order, and that is the
 * order they appear in `rules` output and reports.
 */
export async function loadPlugins(specs: readonly string[], io: CliIO): Promise<LoadedPlugin[]> {
  if (specs.length === 0) return [];
  let plugins: ScannerPlugin[];
  try {
    plugins = await loadScannerPlugins(specs, { cwd: io.cwd });
  } catch (error) {
    // The loader already speaks in operator terms; keep its message verbatim
    // and only guarantee the exit code (64) by re-throwing the CLI's shape.
    throw new CliUsageError(error instanceof Error ? error.message : String(error));
  }
  const builtinIds = new Set(BUILTIN_SCANNERS.map((scanner) => scanner.id));
  return plugins.map((plugin, index) => {
    const spec = specs[index] ?? plugin.id;
    // Checked here rather than only at registration so every command that
    // accepts --plugin (including `plugins`, which never builds an engine)
    // refuses a plugin that would shadow a built-in scanner.
    if (builtinIds.has(plugin.id)) {
      throw new CliUsageError(
        `Plugin "${spec}" uses id "${plugin.id}", which is already taken by a built-in scanner`,
      );
    }
    return { spec, source: resolvePluginSource(spec, io.cwd), plugin };
  });
}

/**
 * The default engine with `loaded` registered after the built-ins. A plugin
 * whose id collides with a built-in (or with an earlier plugin) is rejected by
 * `engine.register`; the spec is added to that message so the operator knows
 * which `--plugin` to fix.
 */
export function engineWithPlugins(loaded: readonly LoadedPlugin[]): ScanEngine {
  const engine = createDefaultEngine();
  for (const entry of loaded) {
    try {
      engine.register(entry.plugin);
    } catch (error) {
      throw new CliUsageError(
        `Cannot register plugin "${entry.spec}": ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }
  return engine;
}

/** Built-ins first, then the plugins in flag order — the roster `rules` lists. */
export function scannerRoster(loaded: readonly LoadedPlugin[]): ScannerPlugin[] {
  return [...BUILTIN_SCANNERS, ...loaded.map((entry) => entry.plugin)];
}
