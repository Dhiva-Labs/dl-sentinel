/**
 * SC015 — unchecked ERC20 transfer return value.
 *
 * ERC20's `transfer`/`transferFrom` return a `bool`. Several widely-held
 * tokens (USDT being the famous one) return `false` instead of reverting on
 * failure, and some return nothing at all — so a bare
 * `token.transfer(to, amount);` statement can silently do nothing while the
 * calling contract books the transfer as done.
 *
 * Precision is the whole design here, because `.transfer(` is also how ETH is
 * sent (`payable(to).transfer(amount)`), which reverts on failure and must
 * never be flagged. Three independent conditions must all hold:
 *
 * 1. **Arity matches ERC20**, not ETH: exactly two top-level arguments for
 *    `transfer`, exactly three for `transferFrom`. `payable(x).transfer(v)`
 *    has one and is excluded structurally, not by naming.
 * 2. **The receiver is recognizably a token**: an `IERC20(...)`-style cast, a
 *    variable declared with an ERC20-ish type (state variable, parameter, or
 *    local), or a variable whose name says so (contains `token`/`erc20`, or is
 *    `asset`/`underlying`). Anything else is left alone.
 * 3. **The result is discarded**: not assigned (`bool ok = ...`), not
 *    destructured, and not wrapped in `require`/`assert`/`if`.
 *
 * The SafeERC20 idiom is the negative by construction: `safeTransfer` /
 * `safeTransferFrom` are different method names and never match, and
 * `require(token.transfer(...))` fails condition 3.
 *
 * Heuristic limits:
 * - Type knowledge is textual. A token held in a variable named `pool` and
 *   typed through an interface this file never names is not recognized.
 * - A `bool` captured and then never checked still counts as checked.
 */

import type { Finding } from '@dl-sentinel/core';
import { createFinding, redactEvidence } from '@dl-sentinel/core';
import type { FunctionInfo } from '../model.js';
import { resolveContractIn, type ResolvedContract } from '../resolve.js';
import { findMatchingParen, splitTopLevel } from '../util.js';
import type { RuleContext, RuleDefinition } from './types.js';

const TRANSFER_CALL_RE = /\.\s*(transferFrom|transfer)\s*\(/g;

/**
 * The receiver expression immediately left of a `.transfer(` — scanned
 * backwards rather than matched with one regex, so arbitrarily nested casts
 * (`IERC20(address(token))`) and indexes (`tokens[i]`) come back whole
 * instead of being truncated at the first inner paren.
 */
function extractReceiver(before: string): { text: string; index: number } | null {
  let i = before.length;
  while (i > 0 && /\s/.test(before.charAt(i - 1))) i--;
  const end = i;
  if (end === 0) return null;

  while (i > 0) {
    const ch = before.charAt(i - 1);
    if (ch === ')' || ch === ']') {
      const open = ch === ')' ? '(' : '[';
      let depth = 0;
      let j = i - 1;
      for (; j >= 0; j--) {
        const c = before.charAt(j);
        if (c === ch) depth++;
        else if (c === open) {
          depth--;
          if (depth === 0) break;
        }
      }
      if (j < 0) return null; // unbalanced: give up rather than guess
      i = j;
      continue;
    }
    if (/[\w$.]/.test(ch)) {
      i--;
      continue;
    }
    break;
  }

  if (i >= end) return null;
  return { text: before.slice(i, end), index: i };
}

const CAPTURE_TUPLE_RE = /\(\s*bool\s+\w+\s*(?:,[^)]*)?\)\s*=\s*$/;
const CAPTURE_ASSIGN_RE = /(?:\bbool\s+\w+|[\w$\]]+)\s*=\s*$/;
const WRAP_RE = /\b(?:require|assert|if|return)\s*\(?\s*!?\s*$/;

/** An ERC20-ish declared type or cast target. */
const TOKEN_TYPE_RE = /^(?:I?ERC20\w*|IToken|ERC777|IERC777)$/;
/** A variable name that says "this is a token". */
const TOKEN_NAME_RE = /token|erc20/i;
const TOKEN_EXACT_NAME_RE = /^_?(?:asset|underlying)$/i;

function isTokenName(name: string): boolean {
  return TOKEN_NAME_RE.test(name) || TOKEN_EXACT_NAME_RE.test(name);
}

/** Local `IERC20 token = ...` / `IERC20 memory t;` declarations inside a body. */
const LOCAL_TOKEN_DECL_RE =
  /\b(I?ERC20\w*|IToken|I?ERC777)\s+(?:memory\s+|storage\s+)?([A-Za-z_$][\w$]*)/g;

/** Every identifier in scope that is recognizably an ERC20 token handle. */
function tokenHandles(resolved: ResolvedContract, fn: FunctionInfo): Set<string> {
  const names = new Set<string>();

  for (const variable of resolved.stateVariables) {
    if (TOKEN_TYPE_RE.test(variable.declaredType) || isTokenName(variable.name)) {
      names.add(variable.name);
    }
  }
  for (const param of fn.declaredParameters) {
    if (TOKEN_TYPE_RE.test(param.type) || isTokenName(param.name)) names.add(param.name);
  }
  for (const line of fn.body) {
    const re = new RegExp(LOCAL_TOKEN_DECL_RE.source, 'g');
    let m: RegExpExecArray | null;
    while ((m = re.exec(line.stripped)) !== null) names.add(m[2]!);
  }

  return names;
}

function receiverIsToken(receiver: string, handles: ReadonlySet<string>): boolean {
  const trimmed = receiver.trim();
  const castMatch = /^([A-Za-z_$][\w$]*)\s*\(/.exec(trimmed);
  if (castMatch) return TOKEN_TYPE_RE.test(castMatch[1]!);
  const base = trimmed.split(/[.[]/)[0]?.trim() ?? '';
  return base !== '' && handles.has(base);
}

/** Number of top-level arguments in the call whose `(` is at `openIndex`. */
function argumentCount(line: string, openIndex: number): number {
  const close = findMatchingParen(line, openIndex);
  if (close === -1) return -1;
  const inner = line.slice(openIndex + 1, close);
  if (inner.trim() === '') return 0;
  return splitTopLevel(inner, ',').length;
}

function evaluate(ctx: RuleContext): Finding[] {
  const findings: Finding[] = [];

  for (const contract of ctx.file.contracts) {
    const resolved = resolveContractIn(ctx.file, contract);

    for (const fn of contract.functions) {
      if (!fn.hasBody) continue;
      const handles = tokenHandles(resolved, fn);
      if (handles.size === 0 && !fn.body.some((l) => /\bI?ERC20\w*\s*\(/.test(l.stripped)))
        continue;

      for (const bl of fn.body) {
        const text = bl.stripped;
        const re = new RegExp(TRANSFER_CALL_RE.source, 'g');
        let m: RegExpExecArray | null;
        while ((m = re.exec(text)) !== null) {
          const method = m[1]!;
          // m[0] is `.transfer(` / `.transferFrom(`, so its last character is the `('.
          const args = argumentCount(text, m.index + m[0].length - 1);
          if (method === 'transfer' ? args !== 2 : args !== 3) continue;

          const before = text.slice(0, m.index);
          const receiver = extractReceiver(before);
          if (!receiver) continue;
          if (!receiverIsToken(receiver.text, handles)) continue;

          const prefix = before.slice(0, receiver.index);
          if (
            CAPTURE_TUPLE_RE.test(prefix) ||
            CAPTURE_ASSIGN_RE.test(prefix) ||
            WRAP_RE.test(prefix)
          )
            continue;

          findings.push(
            createFinding({
              ruleId: 'SC015',
              title: 'Unchecked ERC20 transfer return value',
              description: `Function '${fn.name}' calls .${method}(...) on a token and discards the returned bool. Tokens that report failure by returning false instead of reverting (USDT and others) make this a silent no-op while the contract's own accounting records a successful transfer.`,
              severity: 'medium',
              confidence: 'medium',
              category: 'smart-contract',
              file: ctx.relPath,
              line: bl.line,
              evidence: redactEvidence(bl.original.trim(), []),
              recommendation:
                "Use OpenZeppelin's SafeERC20 (safeTransfer/safeTransferFrom), or capture the returned bool and require() it.",
              references: ['https://swcregistry.io/docs/SWC-104'],
              scanner: 'smart-contract',
              metadata: { function: fn.name, method },
            }),
          );
        }
      }
    }
  }

  return findings;
}

export const sc015UncheckedErc20Transfer: RuleDefinition = {
  meta: {
    id: 'SC015',
    title: 'Unchecked ERC20 transfer return value',
    severity: 'medium',
    defaultConfidence: 'medium',
    category: 'smart-contract',
    description:
      'A bare token.transfer(to, amount) / transferFrom(from, to, amount) statement discards the ERC20 bool return value — neither captured, required, nor wrapped. Only fires when the receiver is recognizably a token (IERC20 cast, ERC20-typed variable, or token/erc20/asset naming) and the argument count matches ERC20 rather than an ETH .transfer.',
    recommendation:
      'Use SafeERC20 (safeTransfer/safeTransferFrom) or check the returned boolean with require().',
    references: ['https://swcregistry.io/docs/SWC-104'],
    // Same weakness class as SC003 and the same mapping SWC-104's own
    // "Relationships" entry cites.
    compliance: { cwe: ['CWE-252'] },
  },
  evaluate,
};
