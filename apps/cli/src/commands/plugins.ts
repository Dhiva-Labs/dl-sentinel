import { CliUsageError, parseFlags } from '../args.js';
import type { ColorFns } from '../colors.js';
import { makeColors, shouldColor } from '../colors.js';
import { EXIT } from '../exit-codes.js';
import type { CliIO } from '../io.js';
import type { LoadedPlugin } from '../plugins.js';
import { PLUGIN_FLAG, loadPlugins, pluginSpecs } from '../plugins.js';
import { parseFormat } from '../parse.js';
import { pluginsHelp } from '../usage.js';

const PLUGINS_FORMATS = ['terminal', 'json'] as const;

/** One plugin as reported by `--format json`. */
interface PluginRow {
  id: string;
  name: string;
  version: string;
  categories: string[];
  rules: number;
  /** The `--plugin` value as typed. */
  spec: string;
  /** Absolute file path, or the package specifier for a bare one. */
  source: string;
}

/**
 * `sentinel plugins --plugin <spec>...` — load each plugin and report what it
 * would contribute, without scanning anything. This is the command to run when
 * reviewing a third-party plugin: it shows the id it claims, the rules it adds
 * and, crucially, the file or package that was actually resolved and imported.
 *
 * Loading a plugin executes it, so this is not a dry run in the sense of "no
 * code ran" — it is a dry run in the sense of "no repository was scanned".
 * Never point it at a plugin you would not run.
 */
export async function runPlugins(argv: readonly string[], io: CliIO): Promise<number> {
  const parsed = parseFlags(argv, [
    { name: 'format', takesValue: true },
    PLUGIN_FLAG,
    { name: 'no-color', takesValue: false },
    { name: 'help', takesValue: false, aliases: ['h'] },
  ]);

  if (parsed.bools.has('help')) {
    io.stdout(`${pluginsHelp()}\n`);
    return EXIT.OK;
  }
  if (parsed.positionals.length > 0) {
    throw new CliUsageError(
      `plugins takes no positional arguments (got "${parsed.positionals[0] ?? ''}"); pass each plugin with --plugin <spec>`,
    );
  }

  const format = parseFormat(parsed.values.get('format'), PLUGINS_FORMATS);
  const specs = pluginSpecs(parsed);
  if (specs.length === 0) {
    // Nothing to list, and nothing to discover: plugins are never loaded from
    // configuration, so the flag is the only possible source.
    io.stderr(
      'No plugins requested. Pass each one with --plugin <path-or-package>, e.g.\n' +
        '  sentinel plugins --plugin ./my-plugin.mjs --plugin dl-sentinel-plugin-acme\n' +
        'Plugins are never loaded from sentinel.yml; see docs/plugins.md.\n',
    );
    return EXIT.USAGE;
  }

  const loaded = await loadPlugins(specs, io);

  if (format === 'json') {
    io.stdout(`${JSON.stringify(toRows(loaded), null, 2)}\n`);
    return EXIT.OK;
  }

  const colors = makeColors(
    shouldColor({ noColorFlag: parsed.bools.has('no-color'), env: io.env, isTTY: io.stdoutIsTTY }),
  );
  io.stdout(`${render(loaded, colors)}\n`);
  return EXIT.OK;
}

function toRows(loaded: readonly LoadedPlugin[]): PluginRow[] {
  return loaded.map((entry) => ({
    id: entry.plugin.id,
    name: entry.plugin.name,
    version: entry.plugin.version,
    categories: [...entry.plugin.categories],
    rules: entry.plugin.rules.length,
    spec: entry.spec,
    source: entry.source,
  }));
}

function render(loaded: readonly LoadedPlugin[], colors: ColorFns): string {
  const lines: string[] = [];
  for (const entry of loaded) {
    const { plugin } = entry;
    const count = plugin.rules.length;
    lines.push('');
    lines.push(
      `${colors.bold(colors.cyan(plugin.id))} ${colors.dim(`${plugin.name} ${plugin.version}`)}`,
    );
    lines.push(`  rules       ${count} rule${count === 1 ? '' : 's'}`);
    lines.push(`  categories  ${plugin.categories.join(', ') || '(none)'}`);
    lines.push(`  source      ${entry.source}`);
  }
  lines.push('');
  lines.push(
    colors.dim(
      `Loaded ${loaded.length} plugin${loaded.length === 1 ? '' : 's'}. Plugins run with the scanner's privileges — only load code you trust.`,
    ),
  );
  return lines.join('\n');
}
