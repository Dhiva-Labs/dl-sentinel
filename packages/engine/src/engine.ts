import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import type {
  FileRef,
  Finding,
  Report,
  ScanContext,
  ScanEvent,
  ScanLogger,
  ScannerError,
  ScannerPlugin,
  SentinelConfig,
} from '@dl-sentinel/core';
import {
  TOOL_NAME,
  TOOL_VERSION,
  applySuppressions,
  computeStats,
  createMatcher,
  dedupeFindings,
  findingFingerprint,
  noopLogger,
  sortFindings,
} from '@dl-sentinel/core';
import { loadConfigWithLogger } from './config.js';
import { discoverFiles } from './discovery.js';
import { abortError, errorMessage, errorStack, throwIfAborted, usageError } from './errors.js';

export interface ScanOptions {
  /** Directory to scan. */
  target: string;
  /** Already-loaded configuration. Wins over `configPath`. */
  config?: SentinelConfig;
  /** Explicit `sentinel.yml` path. Wins over the target-directory lookup. */
  configPath?: string;
  /** Subset of registered scanner ids to run. Unknown ids are a usage error. */
  scanners?: string[];
  /** Cooperative cancellation; an abort makes `scan()` reject with an `AbortError`. */
  signal?: AbortSignal;
  /** Progress callback. Listener exceptions are logged and swallowed. */
  onEvent?: (event: ScanEvent) => void;
  logger?: ScanLogger;
}

export interface ScanEngine {
  /** Register a scanner plugin. Duplicate ids are rejected. */
  register(plugin: ScannerPlugin): void;
  /** Registered plugins, in registration order. */
  plugins(): readonly ScannerPlugin[];
  /** Run every selected scanner over the target and aggregate a report. */
  scan(options: ScanOptions): Promise<Report>;
}

/**
 * Create a scan engine.
 *
 * The engine owns configuration loading, file discovery, per-scanner file
 * filtering, concurrent execution with failure isolation, dedupe/sort/stats,
 * and report assembly. It never executes scanned code and never logs file
 * contents.
 */
export function createEngine(): ScanEngine {
  const registered: ScannerPlugin[] = [];
  const registeredIds = new Set<string>();

  return {
    register(plugin: ScannerPlugin): void {
      if (typeof plugin.id !== 'string' || plugin.id === '') {
        throw usageError('Scanner plugin must have a non-empty id');
      }
      if (registeredIds.has(plugin.id)) {
        throw usageError(`A scanner with id "${plugin.id}" is already registered`);
      }
      registeredIds.add(plugin.id);
      registered.push(plugin);
    },

    plugins(): readonly ScannerPlugin[] {
      return [...registered];
    },

    scan(options: ScanOptions): Promise<Report> {
      return runScan([...registered], options);
    },
  };
}

interface Emitter {
  emit(event: ScanEvent): void;
  /** Stop emitting; called once the scan has settled. */
  close(): void;
}

interface ScannerRunContext {
  rootDir: string;
  files: readonly FileRef[];
  config: SentinelConfig;
  logger: ScanLogger;
  signal: AbortSignal;
  emit: Emitter['emit'];
}

interface ScannerOutcome {
  plugin: ScannerPlugin;
  findings: Finding[];
  error?: ScannerError;
}

async function runScan(plugins: readonly ScannerPlugin[], options: ScanOptions): Promise<Report> {
  const logger = options.logger ?? noopLogger;
  const emitter = createEmitter(options.onEvent, logger);
  const startedAtMs = Date.now();
  const startedAt = new Date(startedAtMs).toISOString();

  throwIfAborted(options.signal);

  const rootDir = await resolveTarget(options.target);
  const config =
    options.config ?? (await loadConfigWithLogger(rootDir, options.configPath, logger));
  const selected = selectScanners(plugins, options.scanners, config, logger);

  const controller = new AbortController();
  const unlink = linkSignal(options.signal, controller);
  const signal = controller.signal;

  try {
    emitter.emit({
      type: 'scan:start',
      target: rootDir,
      scanners: selected.map((plugin) => plugin.id),
    });

    const files = await discoverFiles({ rootDir, config, logger, signal });
    emitter.emit({ type: 'files:discovered', count: files.length });
    throwIfAborted(signal);

    const outcomes = await runScanners(selected, {
      rootDir,
      files,
      config,
      logger,
      signal,
      emit: (event) => emitter.emit(event),
    });

    const deduped = sortFindings(dedupeFindings(outcomes.flatMap((outcome) => outcome.findings)));
    // Suppression is the last finding-model step: drop reviewed findings so the
    // report, stats and events all reflect only the active ones.
    const suppressRules = config.suppress ?? [];
    const { active, suppressed } = applySuppressions(deduped, suppressRules, new Date());
    const errors = outcomes.flatMap((outcome) => (outcome.error ? [outcome.error] : []));
    const finishedAtMs = Date.now();
    const report: Report = {
      tool: { name: TOOL_NAME, version: TOOL_VERSION },
      project: path.basename(rootDir) || rootDir,
      target: rootDir,
      startedAt,
      finishedAt: new Date(finishedAtMs).toISOString(),
      durationMs: finishedAtMs - startedAtMs,
      scannersRun: selected.map((plugin) => plugin.id),
      stats: computeStats(active),
      findings: active,
      errors,
      // Only surface `suppressed` when suppression was actually configured, so
      // reports and consumers that predate this feature are unaffected.
      ...(suppressRules.length > 0 ? { suppressed: suppressed.length } : {}),
      // Surface the resolved policy so consumers (CLI exit codes, the API's
      // policy.violated notification) evaluate the target's own policy.
      policy: config.policy,
    };

    emitter.emit({
      type: 'scan:complete',
      findings: active.length,
      durationMs: report.durationMs,
    });
    return report;
  } finally {
    emitter.close();
    unlink();
  }
}

/**
 * Run every selected scanner concurrently. A scanner that throws is recorded
 * as a `ScannerError` and the scan continues; only cancellation aborts the
 * run, and it does so without waiting for scanners that ignore the signal.
 */
async function runScanners(
  selected: readonly ScannerPlugin[],
  context: ScannerRunContext,
): Promise<ScannerOutcome[]> {
  const tasks = selected.map((plugin) => runScanner(plugin, context));
  const settled = await raceAbort(Promise.allSettled(tasks), context.signal);
  throwIfAborted(context.signal);

  const outcomes: ScannerOutcome[] = [];
  for (let index = 0; index < settled.length; index += 1) {
    const result = settled[index];
    const plugin = selected[index];
    if (result === undefined || plugin === undefined) continue;
    if (result.status === 'fulfilled') {
      outcomes.push(result.value);
      continue;
    }
    // Defensive: runScanner only rejects on cancellation, which was handled above.
    outcomes.push({
      plugin,
      findings: [],
      error: toScannerError(plugin.id, result.reason),
    });
  }
  return outcomes;
}

async function runScanner(
  plugin: ScannerPlugin,
  context: ScannerRunContext,
): Promise<ScannerOutcome> {
  const scanContext: ScanContext = {
    rootDir: context.rootDir,
    files: filesFor(plugin, context.files),
    config: scannerSettings(context.config, plugin.id),
    signal: context.signal,
    logger: context.logger,
    readFile: (ref) => readScannedFile(ref, context.config.maxFileSizeBytes),
  };

  context.emit({ type: 'scanner:start', scanner: plugin.id });
  const startedMs = Date.now();
  try {
    const produced = await plugin.scan(scanContext);
    const findings = attributeFindings(produced, plugin.id, context.logger);
    context.emit({
      type: 'scanner:complete',
      scanner: plugin.id,
      findings: findings.length,
      durationMs: Date.now() - startedMs,
    });
    return { plugin, findings };
  } catch (error) {
    // A throw after cancellation is how scanners stop early — not a failure.
    if (context.signal.aborted) throw abortError(context.signal.reason);
    const scannerError = toScannerError(plugin.id, error);
    context.logger.error(`Scanner "${plugin.id}" failed: ${scannerError.message}`);
    context.emit({ type: 'scanner:error', scanner: plugin.id, message: scannerError.message });
    return { plugin, findings: [], error: scannerError };
  }
}

/** Narrow the discovered files to the ones a scanner asked for (`[]` = all). */
function filesFor(plugin: ScannerPlugin, files: readonly FileRef[]): readonly FileRef[] {
  if (!Array.isArray(plugin.supportedFiles) || plugin.supportedFiles.length === 0) return files;
  const matches = createMatcher(plugin.supportedFiles);
  return files.filter((file) => matches(file.relPath));
}

/** A scanner's own config section, copied so scanners cannot mutate shared state. */
function scannerSettings(config: SentinelConfig, id: string): Record<string, unknown> {
  const section = config.scanners[id];
  return section === undefined ? {} : { ...section };
}

async function readScannedFile(ref: FileRef, maxFileSizeBytes: number): Promise<string> {
  if (ref.size > maxFileSizeBytes) {
    throw new Error(
      `Refusing to read ${ref.relPath}: ${ref.size} bytes exceeds maxFileSizeBytes (${maxFileSizeBytes})`,
    );
  }
  return readFile(ref.absPath, 'utf8');
}

/**
 * Findings are always attributed to the plugin that produced them. A
 * mis-attributed finding is corrected and its fingerprint recomputed, because
 * the scanner id is part of the fingerprint (docs/finding-schema.md).
 */
function attributeFindings(
  findings: readonly Finding[],
  scanner: string,
  logger: ScanLogger,
): Finding[] {
  return findings.map((finding) => {
    if (finding.scanner === scanner) return finding;
    logger.warn(
      `Scanner "${scanner}" returned a finding attributed to "${String(finding.scanner)}"; re-attributing it`,
    );
    const corrected: Finding = { ...finding, scanner };
    return { ...corrected, id: findingFingerprint(corrected) };
  });
}

function toScannerError(scanner: string, error: unknown): ScannerError {
  const stack = errorStack(error);
  return {
    scanner,
    message: errorMessage(error),
    ...(stack === undefined ? {} : { stack }),
  };
}

function selectScanners(
  plugins: readonly ScannerPlugin[],
  requested: readonly string[] | undefined,
  config: SentinelConfig,
  logger: ScanLogger,
): ScannerPlugin[] {
  let chosen = [...plugins];

  if (requested !== undefined) {
    const known = new Set(plugins.map((plugin) => plugin.id));
    const unknown = requested.filter((id) => !known.has(id));
    if (unknown.length > 0) {
      const registered = [...known].join(', ');
      throw usageError(
        `Unknown scanner${unknown.length > 1 ? 's' : ''}: ${unknown.join(', ')}. Registered: ${registered === '' ? '(none)' : registered}`,
      );
    }
    const wanted = new Set(requested);
    chosen = chosen.filter((plugin) => wanted.has(plugin.id));
  }

  return chosen.filter((plugin) => {
    if (config.scanners[plugin.id]?.enabled === false) {
      logger.info(`Scanner "${plugin.id}" is disabled by configuration; skipping`);
      return false;
    }
    return true;
  });
}

async function resolveTarget(target: string): Promise<string> {
  if (typeof target !== 'string' || target.trim() === '') {
    throw usageError('scan(): options.target must be a non-empty directory path');
  }
  const resolved = path.resolve(target);
  let isDirectory: boolean;
  try {
    isDirectory = (await stat(resolved)).isDirectory();
  } catch (error) {
    throw usageError(`Scan target does not exist: ${resolved} (${errorMessage(error)})`);
  }
  if (!isDirectory) {
    throw usageError(`Scan target is not a directory: ${resolved}`);
  }
  return resolved;
}

function createEmitter(
  onEvent: ((event: ScanEvent) => void) | undefined,
  logger: ScanLogger,
): Emitter {
  let active = true;
  return {
    emit(event: ScanEvent): void {
      if (!active || onEvent === undefined) return;
      try {
        onEvent(event);
      } catch (error) {
        logger.warn(`Scan event listener threw: ${errorMessage(error)}`);
      }
    },
    close(): void {
      active = false;
    },
  };
}

/** Mirror an external abort onto the engine's own controller. */
function linkSignal(external: AbortSignal | undefined, controller: AbortController): () => void {
  if (external === undefined) return () => {};
  if (external.aborted) {
    controller.abort(external.reason);
    return () => {};
  }
  const forward = (): void => controller.abort(external.reason);
  external.addEventListener('abort', forward, { once: true });
  return () => external.removeEventListener('abort', forward);
}

/** Resolve with the promise, or reject as soon as the signal aborts. */
async function raceAbort<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) throw abortError(signal.reason);
  let onAbort: (() => void) | undefined;
  const aborted = new Promise<never>((_resolve, reject) => {
    onAbort = () => reject(abortError(signal.reason));
    signal.addEventListener('abort', onAbort, { once: true });
  });
  try {
    return await Promise.race([promise, aborted]);
  } finally {
    if (onAbort !== undefined) signal.removeEventListener('abort', onAbort);
  }
}
