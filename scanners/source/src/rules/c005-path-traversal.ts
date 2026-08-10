import type { RuleModule, RuleHit } from './types.js';
import { findCallSites, splitTopLevel } from '../text.js';
import { resolveArgDynamism } from '../context.js';
import type { FileContext } from '../context.js';

/**
 * C005 -- path traversal risk.
 *
 * Kept deliberately narrow (medium/low, per the finding schema's confidence
 * guidance for heuristic rules): a request/user-ish identifier -- `req`,
 * `request`, `params`, `input`, or `argv` as a whole word, case-insensitive
 * -- appears inside an argument passed to a filesystem read/write/join call.
 *
 * Two shapes are handled differently:
 *  - "join" calls (`path.join`, `path.resolve`, `os.path.join`,
 *    `filepath.Join`, `File.join`) build a path out of multiple segment
 *    arguments by construction, so any segment containing one of the
 *    identifiers is enough -- no separate concatenation evidence is needed.
 *  - Direct read/write calls (`fs.readFile[Sync]`, `open`, `fopen`, `os.Open`,
 *    etc.) need the path argument to be dynamically built (template literal,
 *    concatenation, or one assignment hop back to such an expression) *and*
 *    for that dynamic text to contain one of the identifiers.
 *
 * Known limitation: the identifier list is intentionally short and matched
 * as whole words. A parameter simply named e.g. `filename` or `userInput`
 * (no whole-word match for any listed identifier) will not trigger this
 * rule even if it is effectively the same risk -- widening the list would
 * trade precision for recall in exactly the way this rule is designed not
 * to. See scanners/source's handover notes.
 */

const IDENTIFIER_TOKENS = /\b(?:req|request|params|input|argv)\b/i;

const JOIN_NAMES = ['path.join', 'path.resolve', 'os.path.join', 'filepath.Join', 'File.join'];
const DIRECT_NAMES = [
  'fs.readFile',
  'fs.readFileSync',
  'fs.writeFile',
  'fs.writeFileSync',
  'fs.appendFile',
  'fs.appendFileSync',
  'fs.createReadStream',
  'fs.createWriteStream',
  'fs.open',
  'fs.openSync',
  'open',
  'File.read',
  'File.open',
  'File.write',
  'IO.read',
  'fopen',
  'file_get_contents',
  'file_put_contents',
  'os.Open',
  'os.Create',
  'os.ReadFile',
  'os.WriteFile',
  'ioutil.ReadFile',
  'ioutil.WriteFile',
];

function checkJoinSites(ctx: FileContext): RuleHit[] {
  const hits: RuleHit[] = [];
  for (let i = 0; i < ctx.lines.length; i++) {
    if (ctx.commentMask[i]) continue;
    const line = ctx.lines[i] ?? '';
    const lineStart = ctx.lineStarts[i] ?? 0;

    for (const site of findCallSites(line, JOIN_NAMES, ctx.text, lineStart)) {
      const args = splitTopLevel(site.args, ',');
      if (args.some((a) => IDENTIFIER_TOKENS.test(a))) {
        hits.push({ line: i, column: site.index });
      }
    }
  }
  return hits;
}

function checkDirectSites(ctx: FileContext): RuleHit[] {
  const hits: RuleHit[] = [];
  for (let i = 0; i < ctx.lines.length; i++) {
    if (ctx.commentMask[i]) continue;
    const line = ctx.lines[i] ?? '';
    const lineStart = ctx.lineStarts[i] ?? 0;

    for (const site of findCallSites(line, DIRECT_NAMES, ctx.text, lineStart)) {
      const [firstArg] = splitTopLevel(site.args, ',');
      const result = resolveArgDynamism(ctx, firstArg ?? '', i);
      if (result.dynamic && IDENTIFIER_TOKENS.test(result.text)) {
        hits.push({ line: i, column: site.index });
      }
    }
  }
  return hits;
}

export const c005PathTraversal: RuleModule = {
  meta: {
    id: 'C005',
    title: 'Possible path traversal from a request-ish identifier',
    severity: 'medium',
    defaultConfidence: 'low',
    category: 'source',
    description:
      'A filesystem read, write, or path-join call includes a path segment built ' +
      'from an identifier that looks like it came from a request or user input ' +
      '(req, request, params, input, argv). Without validation, this can allow ' +
      'reading or writing outside the intended directory.',
    recommendation:
      'Validate and normalize the path (resolve it and confirm it stays within an ' +
      'allowed base directory), or use only the basename of the untrusted segment ' +
      'joined onto a fixed, trusted directory.',
    references: [],
  },
  languages: ['js', 'py', 'rb', 'php', 'go'],
  check(ctx) {
    return [...checkJoinSites(ctx), ...checkDirectSites(ctx)];
  },
};
