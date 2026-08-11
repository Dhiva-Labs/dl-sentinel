/**
 * Static help text. Kept plain (no color) so it renders identically whether it
 * lands on a pipe or a terminal, and so tests can assert on stable substrings.
 */
import { TOOL_NAME, TOOL_VERSION } from '@dl-sentinel/core';

export function topLevelHelp(): string {
  return [
    `${TOOL_NAME} v${TOOL_VERSION}`,
    '',
    'Usage: sentinel <command> [options]',
    '',
    'Commands:',
    '  scan [path]        Scan a directory (default: .) and report findings',
    '  baseline [path]    Scan and write a baseline of the current findings',
    '  rules              List every rule from the built-in scanners',
    '  plugins            List the external scanner plugins given with --plugin',
    '  report <file>      Re-render a saved JSON report in another format',
    '  version            Print the tool name and version',
    '',
    'Global options:',
    '  --help, -h         Show help',
    '  --version          Show the tool version',
    '',
    "Run 'sentinel <command> --help' for command-specific options.",
  ].join('\n');
}

export function scanHelp(): string {
  return [
    'Usage: sentinel scan [path] [options]',
    '',
    'Scan a directory (default: .) with the built-in scanners and print a report.',
    '',
    'Options:',
    '  --config <file>      Use an explicit sentinel.yml instead of discovering one',
    '  --format <format>    terminal | json | markdown | sarif (default: terminal)',
    '  --output <file>      Write the report to a file instead of stdout',
    '  --scanners <ids>     Comma-separated subset of scanner ids to run',
    '  --fail-on <sevs>     Comma-separated severities that fail the policy',
    '  --baseline <file>    Report only findings absent from this baseline',
    '  --write-baseline <file>',
    '                       Write a baseline of this scan after reporting',
    '  --plugin <spec>      Load an external scanner plugin (repeatable)',
    '  --quiet              Suppress progress output on stderr',
    '  --no-color           Disable ANSI color',
    '  --help, -h           Show this help',
    '',
    'With --baseline, the exit code reflects only the NEW findings.',
    '',
    '--plugin takes a file path or an installed package name. Plugins run with',
    "this tool's privileges and are never loaded from sentinel.yml; see",
    'docs/plugins.md.',
    '',
    'Exit codes: 0 ok · 1 policy violated · 2 error · 64 usage error',
  ].join('\n');
}

export function baselineHelp(): string {
  return [
    'Usage: sentinel baseline [path] [options]',
    '',
    'Scan a directory (default: .) and write a baseline of the current findings,',
    'so a later `sentinel scan --baseline <file>` reports only new findings.',
    '',
    'Options:',
    '  --config <file>      Use an explicit sentinel.yml instead of discovering one',
    '  --scanners <ids>     Comma-separated subset of scanner ids to run',
    '  --output <file>      Baseline file to write (default: .sentinel-baseline.json)',
    '  --plugin <spec>      Load an external scanner plugin (repeatable)',
    '  --quiet              Suppress the summary line on stderr',
    '  --no-color           Disable ANSI color',
    '  --help, -h           Show this help',
    '',
    'Exit codes: 0 ok · 2 write error · 64 usage error',
  ].join('\n');
}

export function rulesHelp(): string {
  return [
    'Usage: sentinel rules [options]',
    '',
    'List every rule from the built-in scanners, plus any plugin given with',
    '--plugin (listed after the built-ins, in flag order).',
    '',
    'Options:',
    '  --format <format>    terminal | json (default: terminal)',
    '  --scanners <ids>     Comma-separated subset of scanner ids to list',
    '  --plugin <spec>      Load an external scanner plugin (repeatable)',
    '  --no-color           Disable ANSI color',
    '  --help, -h           Show this help',
  ].join('\n');
}

export function pluginsHelp(): string {
  return [
    'Usage: sentinel plugins --plugin <spec> [--plugin <spec>...]',
    '',
    'Load each external scanner plugin and list what it would contribute —',
    'id, name, version, rule count and the file or package actually resolved —',
    'without scanning anything.',
    '',
    'A <spec> is a file path (./dist/plugin.mjs, /opt/plugins/acme.js) or an',
    'installed package name (dl-sentinel-plugin-acme). Plugins are NEVER loaded',
    'from sentinel.yml: a plugin is code, and config can come from the',
    'repository being scanned.',
    '',
    'Options:',
    '  --plugin <spec>      Load an external scanner plugin (repeatable, required)',
    '  --format <format>    terminal | json (default: terminal)',
    '  --no-color           Disable ANSI color',
    '  --help, -h           Show this help',
    '',
    'Listing a plugin imports it, which runs its module code. Only ever point',
    'this at a plugin you trust; see docs/plugins.md.',
    '',
    'Exit codes: 0 ok · 64 usage error (no --plugin, bad spec, invalid plugin)',
  ].join('\n');
}

export function reportHelp(): string {
  return [
    'Usage: sentinel report <file> [options]',
    '',
    'Re-render a previously saved JSON report in another format, without rescanning.',
    '',
    'Options:',
    '  --format <format>    terminal | json | markdown | sarif (default: terminal)',
    '  --output <file>      Write the rendered report to a file instead of stdout',
    '  --no-color           Disable ANSI color',
    '  --help, -h           Show this help',
  ].join('\n');
}

export function versionHelp(): string {
  return [
    'Usage: sentinel version [options]',
    '',
    'Print the tool name and version.',
    '',
    'Options:',
    '  --format <format>    terminal | json (default: terminal)',
    '  --help, -h           Show this help',
  ].join('\n');
}
