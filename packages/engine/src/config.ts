import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { parse as parseYaml } from 'yaml';
import type {
  PolicyConfig,
  ScanLogger,
  ScannerSettings,
  SentinelConfig,
  Severity,
} from '@dl-sentinel/core';
import { SEVERITY_ORDER, defaultConfig } from '@dl-sentinel/core';
import { errorMessage } from './errors.js';
import { stderrLogger } from './logger.js';

/** Config file names looked up in the target directory, in precedence order. */
export const CONFIG_FILENAMES: readonly string[] = ['sentinel.yml', 'sentinel.yaml'];

const TOP_LEVEL_KEYS: readonly string[] = [
  'include',
  'exclude',
  'maxFileSizeBytes',
  'scanners',
  'policy',
];

const VALID_SEVERITIES = new Set<string>(SEVERITY_ORDER);

/**
 * Load `sentinel.yml` (or `sentinel.yaml`) and merge it over
 * {@link defaultConfig}.
 *
 * - `configPath` (if given) wins over the target-directory lookup and must
 *   exist — a missing explicit path is an error, not a fallback to defaults.
 * - No config file in the target directory → pure defaults.
 * - An empty file → pure defaults.
 * - Unparseable YAML, a non-mapping document, or a known key with the wrong
 *   type → throws with the file path in the message.
 * - Unknown top-level keys are warned about and ignored.
 *
 * Warnings go to stderr; use the engine's `scan()` (which threads its own
 * `ScanLogger` through) to capture them instead.
 */
export async function loadConfig(targetDir: string, configPath?: string): Promise<SentinelConfig> {
  return loadConfigWithLogger(targetDir, configPath, stderrLogger);
}

/** {@link loadConfig} with an explicit logger. Used by the engine during a scan. */
export async function loadConfigWithLogger(
  targetDir: string,
  configPath: string | undefined,
  logger: ScanLogger,
): Promise<SentinelConfig> {
  const defaults = defaultConfig();
  const source = await resolveConfigFile(targetDir, configPath);
  if (source === undefined) {
    logger.debug('No sentinel.yml found; using default configuration');
    return defaults;
  }

  let text: string;
  try {
    text = await readFile(source, 'utf8');
  } catch (error) {
    throw new Error(`Cannot read config file ${source}: ${errorMessage(error)}`, { cause: error });
  }

  const raw = parseConfigDocument(text, source);
  if (raw === undefined) return defaults;
  return mergeConfig(defaults, raw, source, logger);
}

async function resolveConfigFile(
  targetDir: string,
  configPath: string | undefined,
): Promise<string | undefined> {
  if (typeof configPath === 'string' && configPath !== '') {
    const resolved = path.resolve(configPath);
    if (!(await isFile(resolved))) {
      throw new Error(`Config file not found: ${resolved}`);
    }
    return resolved;
  }
  const root = path.resolve(targetDir);
  for (const name of CONFIG_FILENAMES) {
    const candidate = path.join(root, name);
    if (await isFile(candidate)) return candidate;
  }
  return undefined;
}

async function isFile(candidate: string): Promise<boolean> {
  try {
    return (await stat(candidate)).isFile();
  } catch {
    return false;
  }
}

/** Parse a config document; `undefined` means "empty file, use defaults". */
function parseConfigDocument(text: string, source: string): Record<string, unknown> | undefined {
  let parsed: unknown;
  try {
    parsed = parseYaml(text);
  } catch (error) {
    throw new Error(`Invalid YAML in ${source}: ${errorMessage(error)}`, { cause: error });
  }
  if (parsed === null || parsed === undefined) return undefined;
  if (!isPlainObject(parsed)) {
    throw new Error(
      `Invalid configuration in ${source}: expected a mapping at the top level, got ${describe(parsed)}`,
    );
  }
  return parsed;
}

function mergeConfig(
  defaults: SentinelConfig,
  raw: Record<string, unknown>,
  source: string,
  logger: ScanLogger,
): SentinelConfig {
  for (const key of Object.keys(raw)) {
    if (!TOP_LEVEL_KEYS.includes(key)) {
      logger.warn(`${source}: unknown configuration key "${key}" (ignored)`);
    }
  }

  return {
    include:
      raw.include === undefined
        ? [...defaults.include]
        : requireStringArray(raw.include, 'include', source),
    exclude:
      raw.exclude === undefined
        ? [...defaults.exclude]
        : requireStringArray(raw.exclude, 'exclude', source),
    maxFileSizeBytes:
      raw.maxFileSizeBytes === undefined
        ? defaults.maxFileSizeBytes
        : requirePositiveNumber(raw.maxFileSizeBytes, 'maxFileSizeBytes', source),
    scanners:
      raw.scanners === undefined
        ? { ...defaults.scanners }
        : mergeScanners(defaults.scanners, raw.scanners, source),
    policy:
      raw.policy === undefined
        ? { failOn: [...defaults.policy.failOn] }
        : mergePolicy(defaults.policy, raw.policy, source, logger),
  };
}

function mergeScanners(
  defaults: Record<string, ScannerSettings>,
  raw: unknown,
  source: string,
): Record<string, ScannerSettings> {
  if (!isPlainObject(raw)) {
    throw new Error(`Invalid configuration in ${source}: "scanners" must be a mapping`);
  }
  const merged: Record<string, ScannerSettings> = {};
  for (const [id, settings] of Object.entries(defaults)) {
    merged[id] = { ...settings };
  }
  for (const [id, settings] of Object.entries(raw)) {
    if (!isPlainObject(settings)) {
      throw new Error(`Invalid configuration in ${source}: "scanners.${id}" must be a mapping`);
    }
    const enabled = settings.enabled;
    if (enabled !== undefined && typeof enabled !== 'boolean') {
      throw new Error(
        `Invalid configuration in ${source}: "scanners.${id}.enabled" must be a boolean`,
      );
    }
    const base = merged[id];
    // Safe cast: ScannerSettings is an open record whose only typed member,
    // `enabled`, was validated above.
    merged[id] = deepMerge(base ?? {}, settings) as ScannerSettings;
  }
  return merged;
}

function mergePolicy(
  defaults: PolicyConfig,
  raw: unknown,
  source: string,
  logger: ScanLogger,
): PolicyConfig {
  if (!isPlainObject(raw)) {
    throw new Error(`Invalid configuration in ${source}: "policy" must be a mapping`);
  }
  for (const key of Object.keys(raw)) {
    if (key !== 'failOn') {
      logger.warn(`${source}: unknown configuration key "policy.${key}" (ignored)`);
    }
  }
  if (raw.failOn === undefined) return { failOn: [...defaults.failOn] };
  return { failOn: requireSeverityArray(raw.failOn, 'policy.failOn', source) };
}

function requireStringArray(value: unknown, key: string, source: string): string[] {
  if (!Array.isArray(value)) {
    throw new Error(`Invalid configuration in ${source}: "${key}" must be a list of strings`);
  }
  const out: string[] = [];
  for (const item of value as unknown[]) {
    if (typeof item !== 'string') {
      throw new Error(
        `Invalid configuration in ${source}: "${key}" must be a list of strings, found ${describe(item)}`,
      );
    }
    out.push(item);
  }
  return out;
}

function requireSeverityArray(value: unknown, key: string, source: string): Severity[] {
  const items = requireStringArray(value, key, source);
  for (const item of items) {
    if (!VALID_SEVERITIES.has(item)) {
      throw new Error(
        `Invalid configuration in ${source}: "${key}" contains unknown severity "${item}" (expected one of ${SEVERITY_ORDER.join(', ')})`,
      );
    }
  }
  return items as Severity[];
}

function requirePositiveNumber(value: unknown, key: string, source: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
    throw new Error(`Invalid configuration in ${source}: "${key}" must be a positive number`);
  }
  return value;
}

/** Recursive merge where mappings merge and everything else (arrays, scalars) replaces. */
function deepMerge(
  base: Record<string, unknown>,
  override: Record<string, unknown>,
): Record<string, unknown> {
  const out: Record<string, unknown> = { ...base };
  for (const [key, value] of Object.entries(override)) {
    const existing = out[key];
    out[key] = isPlainObject(existing) && isPlainObject(value) ? deepMerge(existing, value) : value;
  }
  return out;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function describe(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'a list';
  return `a ${typeof value}`;
}
