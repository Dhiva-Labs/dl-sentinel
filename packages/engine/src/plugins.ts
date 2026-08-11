/**
 * Loading of third-party scanner plugins (docs/architecture.md §Plugins,
 * docs/plugins.md).
 *
 * **Trust boundary.** A plugin is operator-chosen executable code: importing one
 * runs it with the scanner's privileges. This module is therefore only ever
 * reached from explicit operator input — the CLI's repeatable `--plugin` flag or
 * the API server's `SENTINEL_PLUGINS` environment variable. It is NEVER reached
 * from a configuration file, not even an explicit `--config` one, because config
 * can live inside the repository being scanned and a scanned repository must
 * never be able to execute code through the scanner. (`sentinel.yml`'s `plugins`
 * key is ignored with a warning; see `config.ts`.)
 *
 * Everything that can go wrong here — an unresolvable spec, a module that throws
 * while importing, a missing or malformed default export, two plugins claiming
 * one id — is a `UsageError`: an operator configuration mistake, mapped by the
 * CLI to exit 64 and by the API server to a fatal startup failure. Failure
 * messages name the spec and the offending field, and never carry a stack trace
 * or a fragment of the plugin's source.
 */
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import type { Confidence, ScannerPlugin, Severity } from '@dl-sentinel/core';
import { SEVERITY_ORDER } from '@dl-sentinel/core';
import { errorMessage, usageError } from './errors.js';

/** Valid `RuleMeta.defaultConfidence` values, in descending strength. */
const CONFIDENCE_VALUES: readonly Confidence[] = ['high', 'medium', 'low'];

/** Extensions that make an extension-less-looking spec a file rather than a package. */
const MODULE_FILE_EXTENSIONS: readonly string[] = ['.js', '.mjs', '.cjs'];

/** The string fields every rule must carry. */
const RULE_TEXT_FIELDS: readonly string[] = ['id', 'title', 'description', 'recommendation'];

/** Longest value echoed back in a validation message (see {@link quote}). */
const MAX_QUOTED_LENGTH = 40;

export interface LoadPluginOptions {
  /** Directory a relative spec resolves against. Defaults to `process.cwd()`. */
  cwd?: string;
}

/**
 * True when `spec` names a file rather than a package: it starts with `.` or is
 * absolute, or it ends in a JavaScript module extension (so `dist/plugin.mjs`
 * works without a leading `./`). Everything else — `dl-sentinel-plugin-acme`,
 * `@acme/sentinel-plugin`, `pkg/subpath` — is a bare package specifier and is
 * handed to the module resolver untouched.
 */
function isPathSpec(spec: string): boolean {
  if (spec.startsWith('.') || spec.startsWith('/') || path.isAbsolute(spec)) return true;
  const lower = spec.toLowerCase();
  return MODULE_FILE_EXTENSIONS.some((extension) => lower.endsWith(extension));
}

/**
 * What a spec resolves to, for display: an absolute path for a path-like spec,
 * or the package specifier unchanged. Used by `sentinel plugins` to show the
 * operator exactly which file or package would be imported.
 */
export function resolvePluginSource(spec: string, cwd?: string): string {
  const trimmed = spec.trim();
  return isPathSpec(trimmed) ? path.resolve(cwd ?? process.cwd(), trimmed) : trimmed;
}

/**
 * Import `spec` and return its validated default export.
 *
 * Resolution: a path-like spec (see {@link isPathSpec}) is resolved against
 * `options.cwd` and imported as a `file:` URL; anything else is imported as a
 * bare package specifier. The module is imported exactly once per process (the
 * module cache is Node's), so loading the same spec twice yields the same object
 * — which is why {@link loadScannerPlugins} rejects it as a duplicate id.
 */
export async function loadScannerPlugin(
  spec: string,
  options: LoadPluginOptions = {},
): Promise<ScannerPlugin> {
  if (typeof spec !== 'string' || spec.trim() === '') {
    throw usageError('A plugin spec must be a non-empty file path or package name');
  }
  const trimmed = spec.trim();
  const source = resolvePluginSource(trimmed, options.cwd);
  const target = isPathSpec(trimmed) ? pathToFileURL(source).href : source;
  const where = source === trimmed ? `"${trimmed}"` : `"${trimmed}" (${source})`;

  let module: unknown;
  try {
    module = (await import(target)) as unknown;
  } catch (error) {
    // Only the thrown message travels — never a stack, never module source.
    throw usageError(`Cannot load plugin ${where}: ${errorMessage(error)}`);
  }

  const exported = isRecord(module) ? module.default : undefined;
  if (exported === undefined) {
    throw usageError(
      `Plugin ${where} has no default export: a plugin module must default-export a ScannerPlugin (see docs/plugins.md)`,
    );
  }

  validateScannerPlugin(exported, trimmed);
  return exported;
}

/**
 * Load several specs in order, rejecting two plugins that claim the same id.
 * The returned array preserves the order the specs were given, which is the
 * order they are registered in and therefore the order they appear in `rules`
 * output and reports (after the built-ins).
 *
 * Collisions with *built-in* scanner ids are not detected here — the engine has
 * no opinion about which scanners an app registers — but `engine.register()`
 * rejects them, and both apps surface that as a usage error naming the spec.
 */
export async function loadScannerPlugins(
  specs: readonly string[],
  options: LoadPluginOptions = {},
): Promise<ScannerPlugin[]> {
  const loaded: ScannerPlugin[] = [];
  const specById = new Map<string, string>();
  for (const spec of specs) {
    // Sequential on purpose: the first bad spec fails the whole load, and the
    // error should name that spec rather than whichever import lost a race.
    const plugin = await loadScannerPlugin(spec, options);
    const previous = specById.get(plugin.id);
    if (previous !== undefined) {
      throw usageError(
        `Duplicate plugin id "${plugin.id}": "${spec}" declares the same id as "${previous}"`,
      );
    }
    specById.set(plugin.id, spec);
    loaded.push(plugin);
  }
  return loaded;
}

/**
 * Assert that `value` is a usable {@link ScannerPlugin}, field by field and rule
 * by rule. Throws a `UsageError` naming the first offending field.
 *
 * The loader runs this on every dynamically imported plugin; callers that build
 * a plugin some other way (an embedder passing one to the API server, a plugin's
 * own test suite) should run it too — it is the single definition of "well
 * formed" for the plugin contract.
 *
 * @param label Optional spec/name used in the message, e.g. the `--plugin` value.
 */
export function validateScannerPlugin(
  value: unknown,
  label?: string,
): asserts value is ScannerPlugin {
  const subject = label === undefined ? 'Invalid scanner plugin' : `Invalid plugin "${label}"`;
  const fail = (detail: string): never => {
    throw usageError(`${subject}: ${detail}`);
  };

  if (!isRecord(value)) {
    fail(`the default export must be a ScannerPlugin object (got ${describe(value)})`);
    return;
  }

  requireNonEmptyString(value.id, 'id', fail);
  requireNonEmptyString(value.name, 'name', fail);
  requireNonEmptyString(value.version, 'version', fail);
  requireStringArray(value.categories, 'categories', fail);
  requireStringArray(value.supportedFiles, 'supportedFiles', fail);

  if (!Array.isArray(value.rules)) {
    fail(`"rules" must be an array of rule descriptors (got ${describe(value.rules)})`);
    return;
  }
  (value.rules as readonly unknown[]).forEach((rule, index) => validateRule(rule, index, fail));

  if (typeof value.scan !== 'function') {
    fail(`"scan" must be a function (got ${describe(value.scan)})`);
  }
}

/** Validate one `RuleMeta` entry of a plugin's `rules` array. */
function validateRule(rule: unknown, index: number, fail: (detail: string) => never): void {
  const at = `rules[${index}]`;
  if (!isRecord(rule)) {
    fail(`"${at}" must be a rule object (got ${describe(rule)})`);
    return;
  }
  for (const field of RULE_TEXT_FIELDS) {
    requireNonEmptyString(rule[field], `${at}.${field}`, fail);
  }
  requireNonEmptyString(rule.category, `${at}.category`, fail);
  requireEnum(rule.severity, SEVERITY_ORDER, `${at}.severity`, fail);
  requireEnum(rule.defaultConfidence, CONFIDENCE_VALUES, `${at}.defaultConfidence`, fail);
  if (rule.references !== undefined) {
    requireStringArray(rule.references, `${at}.references`, fail);
  }
  if (rule.compliance !== undefined) {
    if (!isRecord(rule.compliance)) {
      fail(`"${at}.compliance" must be an object (got ${describe(rule.compliance)})`);
      return;
    }
    for (const framework of ['cwe', 'owasp']) {
      const mapped = rule.compliance[framework];
      if (mapped !== undefined) {
        requireStringArray(mapped, `${at}.compliance.${framework}`, fail);
      }
    }
  }
}

function requireNonEmptyString(
  value: unknown,
  field: string,
  fail: (detail: string) => never,
): void {
  if (typeof value !== 'string' || value.trim() === '') {
    fail(`"${field}" must be a non-empty string (got ${describe(value)})`);
  }
}

function requireStringArray(value: unknown, field: string, fail: (detail: string) => never): void {
  if (!Array.isArray(value)) {
    fail(`"${field}" must be an array of strings (got ${describe(value)})`);
    return;
  }
  (value as readonly unknown[]).forEach((item, index) => {
    if (typeof item !== 'string') {
      fail(`"${field}[${index}]" must be a string (got ${describe(item)})`);
    }
  });
}

function requireEnum(
  value: unknown,
  allowed: readonly (Severity | Confidence)[],
  field: string,
  fail: (detail: string) => never,
): void {
  if (typeof value !== 'string' || !(allowed as readonly string[]).includes(value)) {
    fail(`"${field}" must be one of ${allowed.join(', ')} (got ${describe(value)})`);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Describe an unexpected value for an error message. Strings are quoted but
 * truncated and stripped of control characters: a plugin's own data must never
 * be able to turn a validation message into a dump of module content.
 */
function describe(value: unknown): string {
  if (value === undefined) return 'nothing';
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'an array';
  if (typeof value === 'string') return quote(value);
  if (typeof value === 'function') return 'a function';
  return `a ${typeof value}`;
}

function quote(value: string): string {
  const flattened = value.replace(/[\u0000-\u001f\u007f]/g, ' ');
  const clipped =
    flattened.length > MAX_QUOTED_LENGTH ? `${flattened.slice(0, MAX_QUOTED_LENGTH)}…` : flattened;
  return `"${clipped}"`;
}
