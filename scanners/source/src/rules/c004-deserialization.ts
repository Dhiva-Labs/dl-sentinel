import type { RuleModule, RuleHit } from './types.js';
import { findCallSites, isSimpleLiteral } from '../text.js';
import type { FileContext } from '../context.js';

/**
 * C004 -- insecure deserialization.
 *
 * - Python: `pickle.loads(...)` / `pickle.load(...)` are flagged
 *   unconditionally -- unpickling is unsafe regardless of the argument,
 *   since the risk is in what the *serialized bytes* can construct, not
 *   whether the Python expression fetching them looks like a literal.
 *   `yaml.load(...)` is flagged unless the call passes a `Loader=` keyword
 *   argument (PyYAML's documented safe usage); `yaml.safe_load(...)` is a
 *   different name and never matches.
 * - Ruby: `Marshal.load(...)` on a non-literal argument (a stand-in for
 *   "data that presumably came from outside the process" -- a literal
 *   argument has no external data to speak of).
 * - PHP: `unserialize(...)` on a non-literal argument.
 */

function checkPython(ctx: FileContext): RuleHit[] {
  const hits: RuleHit[] = [];
  for (let i = 0; i < ctx.lines.length; i++) {
    if (ctx.commentMask[i]) continue;
    const line = ctx.lines[i] ?? '';
    const lineStart = ctx.lineStarts[i] ?? 0;

    for (const site of findCallSites(line, ['pickle.loads', 'pickle.load'], ctx.text, lineStart)) {
      hits.push({ line: i, column: site.index });
    }

    for (const site of findCallSites(line, ['yaml.load'], ctx.text, lineStart)) {
      if (!/\bLoader\s*=/.test(site.args)) {
        hits.push({ line: i, column: site.index });
      }
    }
  }
  return hits;
}

function checkRuby(ctx: FileContext): RuleHit[] {
  const hits: RuleHit[] = [];
  for (let i = 0; i < ctx.lines.length; i++) {
    if (ctx.commentMask[i]) continue;
    const line = ctx.lines[i] ?? '';
    const lineStart = ctx.lineStarts[i] ?? 0;

    for (const site of findCallSites(line, ['Marshal.load'], ctx.text, lineStart)) {
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

    for (const site of findCallSites(line, ['unserialize'], ctx.text, lineStart)) {
      if (!isSimpleLiteral(site.args)) {
        hits.push({ line: i, column: site.index });
      }
    }
  }
  return hits;
}

export const c004Deserialization: RuleModule = {
  meta: {
    id: 'C004',
    title: 'Insecure deserialization',
    severity: 'high',
    defaultConfidence: 'high',
    category: 'source',
    description:
      'Untrusted data is deserialized with an API that can execute arbitrary code as ' +
      'a side effect of reconstructing objects (Python pickle.load/loads, PyYAML ' +
      'yaml.load without a safe Loader, Ruby Marshal.load, PHP unserialize). If the ' +
      'serialized bytes are attacker-controlled, this is a remote code execution ' +
      'vulnerability.',
    recommendation:
      'Use a safe, data-only format instead (JSON, or yaml.safe_load / ' +
      'yaml.load(data, Loader=yaml.SafeLoader) for YAML). If a native serialization ' +
      'format is unavoidable, sign or encrypt the payload and verify it before ' +
      'deserializing.',
    references: [],
  },
  languages: ['py', 'rb', 'php'],
  check(ctx) {
    switch (ctx.lang) {
      case 'py':
        return checkPython(ctx);
      case 'rb':
        return checkRuby(ctx);
      case 'php':
        return checkPhp(ctx);
      default:
        return [];
    }
  },
};
