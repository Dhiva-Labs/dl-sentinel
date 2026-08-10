import { TOOL_NAME, TOOL_VERSION } from '@dl-sentinel/core';
import { CliUsageError, parseFlags } from '../args.js';
import { EXIT } from '../exit-codes.js';
import type { CliIO } from '../io.js';
import { parseFormat } from '../parse.js';
import { versionHelp } from '../usage.js';

const VERSION_FORMATS = ['terminal', 'json'] as const;

/** `sentinel version` — print the tool name and version. */
export function runVersion(argv: readonly string[], io: CliIO): number {
  const parsed = parseFlags(argv, [
    { name: 'format', takesValue: true },
    { name: 'help', takesValue: false, aliases: ['h'] },
  ]);

  if (parsed.bools.has('help')) {
    io.stdout(`${versionHelp()}\n`);
    return EXIT.OK;
  }
  if (parsed.positionals.length > 0) {
    throw new CliUsageError(
      `version takes no positional arguments (got "${parsed.positionals[0] ?? ''}")`,
    );
  }

  const format = parseFormat(parsed.values.get('format'), VERSION_FORMATS);
  if (format === 'json') {
    io.stdout(`${JSON.stringify({ name: TOOL_NAME, version: TOOL_VERSION }, null, 2)}\n`);
  } else {
    io.stdout(`${TOOL_NAME} ${TOOL_VERSION}\n`);
  }
  return EXIT.OK;
}
