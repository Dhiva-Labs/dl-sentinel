import type { RuleModule, RuleHit } from './types.js';
import { findCallSites, splitTopLevel } from '../text.js';
import { resolveArgDynamism } from '../context.js';
import type { FileContext } from '../context.js';

/**
 * C001 -- command execution from string building.
 *
 * - JS/TS: `exec` / `execSync` (bare or qualified, e.g. `child_process.exec`)
 *   whose command argument is built from a template literal or `+`
 *   concatenation (directly, or one assignment hop back -- see
 *   `resolveArgDynamism`). A constant string argument is not flagged.
 * - Python: `os.system(...)` with a dynamic argument, or
 *   `subprocess.{run,call,Popen,check_call,check_output}(...)` when the
 *   call also passes `shell=True` *and* the command argument is dynamic.
 *   `shell=True` is required because without it these APIs do not invoke a
 *   shell, so string-building alone is not the same class of risk.
 * - Ruby: a backtick command string containing `#{...}` interpolation.
 */

const JS_NAMES = ['exec', 'execSync'];
const PY_SHELL_CALLS = [
  'subprocess.run',
  'subprocess.call',
  'subprocess.Popen',
  'subprocess.check_call',
  'subprocess.check_output',
];
const RUBY_BACKTICK_INTERP = /`[^`\n]*#\{[^`\n]*`/g;

function checkJs(ctx: FileContext): RuleHit[] {
  const hits: RuleHit[] = [];
  for (let i = 0; i < ctx.lines.length; i++) {
    if (ctx.commentMask[i]) continue;
    const line = ctx.lines[i] ?? '';
    const lineStart = ctx.lineStarts[i] ?? 0;
    for (const site of findCallSites(line, JS_NAMES, ctx.text, lineStart)) {
      const [firstArg] = splitTopLevel(site.args, ',');
      const result = resolveArgDynamism(ctx, firstArg ?? '', i);
      if (result.dynamic) {
        hits.push({ line: i, column: site.index });
      }
    }
  }
  return hits;
}

function checkPython(ctx: FileContext): RuleHit[] {
  const hits: RuleHit[] = [];
  for (let i = 0; i < ctx.lines.length; i++) {
    if (ctx.commentMask[i]) continue;
    const line = ctx.lines[i] ?? '';
    const lineStart = ctx.lineStarts[i] ?? 0;

    for (const site of findCallSites(line, ['os.system'], ctx.text, lineStart)) {
      const [firstArg] = splitTopLevel(site.args, ',');
      const result = resolveArgDynamism(ctx, firstArg ?? '', i);
      if (result.dynamic) hits.push({ line: i, column: site.index });
    }

    for (const site of findCallSites(line, PY_SHELL_CALLS, ctx.text, lineStart)) {
      if (!/shell\s*=\s*True\b/.test(site.args)) continue;
      const [firstArg] = splitTopLevel(site.args, ',');
      const result = resolveArgDynamism(ctx, (firstArg ?? '').trim(), i);
      if (result.dynamic) hits.push({ line: i, column: site.index });
    }
  }
  return hits;
}

function checkRuby(ctx: FileContext): RuleHit[] {
  const hits: RuleHit[] = [];
  for (let i = 0; i < ctx.lines.length; i++) {
    if (ctx.commentMask[i]) continue;
    const line = ctx.lines[i] ?? '';
    RUBY_BACKTICK_INTERP.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = RUBY_BACKTICK_INTERP.exec(line))) {
      hits.push({ line: i, column: m.index });
    }
  }
  return hits;
}

export const c001CommandExec: RuleModule = {
  meta: {
    id: 'C001',
    title: 'Command execution built from a dynamic string',
    severity: 'high',
    defaultConfidence: 'medium',
    category: 'source',
    description:
      'A shell command is executed via child_process exec/execSync, os.system, ' +
      'subprocess with shell=True, or Ruby backtick interpolation, where the command ' +
      'text is built from a template literal, string concatenation, or interpolation ' +
      'rather than a fixed constant. If any part of that string is influenced by ' +
      'external input, this is a command injection vulnerability.',
    recommendation:
      'Avoid building shell command strings dynamically. Prefer APIs that take an ' +
      'argv array without invoking a shell (execFile/spawn with an args array in ' +
      'Node.js, subprocess.run([...], shell=False) in Python). If a shell is ' +
      'unavoidable, strictly allowlist and escape every interpolated value.',
    references: [],
  },
  languages: ['js', 'py', 'rb'],
  check(ctx) {
    switch (ctx.lang) {
      case 'js':
        return checkJs(ctx);
      case 'py':
        return checkPython(ctx);
      case 'rb':
        return checkRuby(ctx);
      default:
        return [];
    }
  },
};
