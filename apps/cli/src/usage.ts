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
    '  --quiet              Suppress progress output on stderr',
    '  --no-color           Disable ANSI color',
    '  --help, -h           Show this help',
    '',
    'With --baseline, the exit code reflects only the NEW findings.',
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
    'List every rule from the built-in scanners.',
    '',
    'Options:',
    '  --format <format>    terminal | json (default: terminal)',
    '  --scanners <ids>     Comma-separated subset of scanner ids to list',
    '  --no-color           Disable ANSI color',
    '  --help, -h           Show this help',
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
