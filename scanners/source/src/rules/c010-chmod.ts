import type { RuleModule, RuleHit } from './types.js';
import { findCallSites } from '../text.js';

/**
 * C010 -- world-writable file modes.
 *
 * A `chmod`-family call (bare `chmod`, `fs.chmod`/`fs.chmodSync`,
 * `os.chmod`, `File.chmod`/`FileUtils.chmod`, or Go's `os.Chmod`) whose
 * argument list contains a world-writable mode literal: 777/666 in octal
 * (`0o777`, `0777`) or decimal (`777`), or the 666 variants. This is
 * language-agnostic by construction (mode literals look the same
 * everywhere), so a single check covers every supported language.
 */

const SINK_NAMES = ['chmod', 'chmodSync', 'os.Chmod'];
const WORLD_WRITABLE_MODE = /\b(?:0o777|0777|777|0o666|0666|666)\b/;

export const c010Chmod: RuleModule = {
  meta: {
    id: 'C010',
    title: 'World-writable file permissions',
    severity: 'medium',
    defaultConfidence: 'high',
    category: 'source',
    description:
      'A chmod call sets a world-writable (777 or 666) permission mode. Any local ' +
      'user or process can then modify the file or directory, which is rarely ' +
      'intentional and can be a privilege-escalation or tampering vector.',
    recommendation:
      'Use the narrowest mode that works (e.g. 0o600/0o644 for files, 0o700/0o755 for ' +
      'directories); grant group/other write access only when specifically required.',
    references: [],
  },
  languages: ['js', 'py', 'rb', 'php', 'go', 'java'],
  check(ctx) {
    const hits: RuleHit[] = [];
    for (let i = 0; i < ctx.lines.length; i++) {
      if (ctx.commentMask[i]) continue;
      const line = ctx.lines[i] ?? '';
      const lineStart = ctx.lineStarts[i] ?? 0;
      for (const site of findCallSites(line, SINK_NAMES, ctx.text, lineStart)) {
        if (WORLD_WRITABLE_MODE.test(site.args)) {
          hits.push({ line: i, column: site.index });
        }
      }
    }
    return hits;
  },
};
