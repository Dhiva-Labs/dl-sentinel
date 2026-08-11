import type { RuleModule, RuleHit } from './types.js';
import { findCallSites, isSimpleLiteral } from '../text.js';
import type { FileContext } from '../context.js';

/**
 * C002 -- eval / dynamic code execution.
 *
 * - JS/TS: any call to `eval(...)` or `new Function(...)` is flagged
 *   unconditionally. Unlike C001, there is no "constant string" exception:
 *   both APIs are almost never appropriate in application code regardless
 *   of what is currently passed to them (the same stance ESLint's `no-eval`
 *   takes).
 * - Python: `eval(...)` / `exec(...)` are flagged only when the argument is
 *   not a simple literal -- `eval("1")` is inert; `eval(user_input)` is not.
 * - PHP: any call to `eval(...)` is flagged unconditionally.
 */

const NEW_FUNCTION = /\bnew\s+Function\s*\(/g;

function checkJs(ctx: FileContext): RuleHit[] {
  const hits: RuleHit[] = [];
  for (let i = 0; i < ctx.lines.length; i++) {
    if (ctx.commentMask[i]) continue;
    const line = ctx.lines[i] ?? '';
    const lineStart = ctx.lineStarts[i] ?? 0;

    for (const site of findCallSites(line, ['eval'], ctx.text, lineStart)) {
      hits.push({ line: i, column: site.index });
    }

    NEW_FUNCTION.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = NEW_FUNCTION.exec(line))) {
      hits.push({ line: i, column: m.index });
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

    for (const site of findCallSites(line, ['eval', 'exec'], ctx.text, lineStart)) {
      if (!isSimpleLiteral(site.args)) {
        hits.push({ line: i, column: site.index });
      }
    }
  }
  return hits;
}

function checkPhp(ctx: FileContext): RuleHit[] {
  const hits: RuleHit[] = [];
  for (let i = 0; i < ctx.lines.length; i++) {
    if (ctx.commentMask[i]) continue;
    const line = ctx.lines[i] ?? '';
    const lineStart = ctx.lineStarts[i] ?? 0;

    for (const site of findCallSites(line, ['eval'], ctx.text, lineStart)) {
      hits.push({ line: i, column: site.index });
    }
  }
  return hits;
}

export const c002Eval: RuleModule = {
  meta: {
    id: 'C002',
    title: 'Dynamic code execution',
    severity: 'high',
    defaultConfidence: 'medium',
    category: 'source',
    description:
      'The code evaluates a string as a program at runtime (JavaScript eval()/new ' +
      'Function(), Python eval()/exec() on a non-literal argument, or PHP eval()). ' +
      'If any part of the evaluated text is influenced by external input, this is ' +
      'an arbitrary code execution vulnerability.',
    recommendation:
      'Remove the dynamic evaluation. Use JSON.parse for data, an explicit dispatch ' +
      'table instead of building code strings, or a safe expression evaluator scoped ' +
      'to the exact operations required.',
    references: [],
    compliance: { cwe: ['CWE-95'], owasp: ['A03:2021'] },
  },
  languages: ['js', 'py', 'php'],
  check(ctx) {
    switch (ctx.lang) {
      case 'js':
        return checkJs(ctx);
      case 'py':
        return checkPython(ctx);
      case 'php':
        return checkPhp(ctx);
      default:
        return [];
    }
  },
};
