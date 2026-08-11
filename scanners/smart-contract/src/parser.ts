/**
 * Line-based Solidity parser.
 *
 * This is deliberately NOT a full Solidity grammar/AST. It is a single-pass,
 * brace-depth-tracking scanner over comment/string-stripped source that
 * recovers just what the SC001-SC012 rules need: contract/interface/library
 * boundaries, per-function metadata (name, visibility, mutability,
 * modifiers, parameters, body lines), top-level state variable names, and
 * pragma constraints. See docs/scanner-interface.md and the rule catalog in
 * the mission brief for the exact fields each rule consumes.
 *
 * Design notes (also see per-function doc comments below):
 * - A single character-by-character pass tracks brace depth and, in the same
 *   pass, accumulates a "current statement" buffer that resets on `{`, `}`,
 *   and `;`. At the moment a `{` is seen, that buffer IS the header text of
 *   whatever is being opened (contract/function/modifier/struct/if/for/...),
 *   which is what makes multi-line headers (long parameter lists, etc.) work
 *   for free — the buffer just keeps growing across lines until a boundary.
 * - Only ONE frame kind actually matters for body-line collection: at most
 *   one function frame can be open at a time (Solidity does not nest function
 *   declarations), so a single `currentFunctionFrame` pointer (rather than a
 *   stack search) is enough to attribute lines to the right function.
 * - The parser never throws for structurally malformed input (unbalanced
 *   braces, unterminated constructs). Depth is clamped at 0 and problems are
 *   recorded in `warnings`; callers (the scanner's `index.ts`) additionally
 *   wrap parsing in a try/catch as defense in depth for anything
 *   unanticipated, per the "malformed .sol must warn+skip, not crash"
 *   requirement.
 */

import type {
  ContractInfo,
  ContractKind,
  FunctionInfo,
  ModifierInfo,
  ParameterInfo,
  ParsedSolidityFile,
  PragmaInfo,
  SourceLine,
  StateMutability,
  Visibility,
} from './model.js';
import { allowsPreVersion } from './pragma.js';
import { stripCommentsAndStrings } from './strip.js';
import { findMatchingParen, splitTopLevel } from './util.js';

const VISIBILITY_KEYWORDS = new Set<Visibility>(['public', 'external', 'internal', 'private']);
const MUTABILITY_KEYWORDS = new Set<StateMutability>(['view', 'pure', 'payable']);
const IGNORED_HEADER_TOKENS = new Set(['virtual', 'override']);

const CONTRACT_OPEN_RE = /\b(abstract\s+contract|contract|interface|library)\s+([A-Za-z_$][\w$]*)/;
const EXCLUDED_STATEMENT_START_RE =
  /^(function|constructor|receive|fallback|modifier|event|struct|enum|using|import|pragma|error|contract|interface|library|abstract)\b/i;

interface Frame {
  kind: ContractKind | 'function' | 'modifier' | 'other';
  /** Brace depth of the frame's *contents* (i.e. depth right after its opening '{'). */
  depth: number;
}

interface ContractFrame extends Frame {
  kind: ContractKind;
  info: ContractInfo;
}

interface FunctionFrame extends Frame {
  kind: 'function';
  info: FunctionInfo;
}

interface ModifierFrame extends Frame {
  kind: 'modifier';
  info: ModifierInfo;
}

function isContractFrame(frame: Frame | undefined): frame is ContractFrame {
  return (
    frame !== undefined &&
    (frame.kind === 'contract' ||
      frame.kind === 'interface' ||
      frame.kind === 'library' ||
      frame.kind === 'abstract')
  );
}

/** Parse `pragma solidity <constraint>;` statements out of the stripped lines. */
function extractPragmas(lines: readonly SourceLine[]): PragmaInfo[] {
  const pragmas: PragmaInfo[] = [];
  const re = /^\s*pragma\s+solidity\s+([^;]+);/;
  for (const l of lines) {
    const m = re.exec(l.stripped);
    if (m) {
      pragmas.push({ raw: (m[1] ?? '').trim(), line: l.line, fullStatement: l.original });
    }
  }
  return pragmas;
}

/**
 * Pre-0.5 Solidity defaults an omitted function visibility to `public`.
 * Solidity >=0.5 requires an explicit visibility (omission does not
 * compile), so encountering one here means either malformed input or a
 * pragma-less file; we still default to `public`, the safer assumption for a
 * security scanner (never silently narrow to internal/private on unknown
 * input).
 */
function defaultVisibilityFor(pragmas: readonly PragmaInfo[]): Visibility {
  if (pragmas.some((p) => allowsPreVersion(p.raw, 0, 5))) {
    return 'public';
  }
  return 'public';
}

interface HeaderTokens {
  name: string;
  isConstructor: boolean;
  visibility?: Visibility;
  stateMutability?: StateMutability;
  modifiers: string[];
  /** Raw text between the parameter list's parens, unparsed. */
  parametersRaw: string;
}

/** Tokenize a modifier-list tail (after the parameter list, before `{`/`;`), skipping any `returns (...)`. */
function tokenizeTail(tail: string): string[] {
  let text = tail;
  const returnsMatch = /\breturns\b/.exec(text);
  if (returnsMatch) {
    const parenIdx = text.indexOf('(', returnsMatch.index);
    if (parenIdx !== -1) {
      const closeIdx = findMatchingParen(text, parenIdx);
      if (closeIdx !== -1) {
        text = text.slice(0, returnsMatch.index) + text.slice(closeIdx + 1);
      } else {
        text = text.slice(0, returnsMatch.index);
      }
    } else {
      text = text.slice(0, returnsMatch.index);
    }
  }

  const tokens: string[] = [];
  const idRe = /[A-Za-z_$][\w$]*/g;
  let m: RegExpExecArray | null;
  while ((m = idRe.exec(text)) !== null) {
    tokens.push(m[0]);
    // Skip a following call-args group, e.g. onlyRole(ADMIN_ROLE), so its
    // contents are never mistaken for additional bare modifier tokens.
    let k = idRe.lastIndex;
    while (k < text.length && /\s/.test(text.charAt(k))) k++;
    if (text.charAt(k) === '(') {
      const close = findMatchingParen(text, k);
      if (close !== -1) idRe.lastIndex = close + 1;
    }
  }
  return tokens;
}

/** Parse a function/constructor/receive/fallback header (from its keyword up to, not including, `{`/`;`). */
function parseHeader(headerText: string): HeaderTokens | null {
  const trimmed = headerText.trim();
  let name: string;
  let isConstructor = false;
  let afterKeywordIdx: number;

  const fnMatch = /^function\b/i.exec(trimmed);
  const ctorMatch = /^constructor\b/i.exec(trimmed);
  const receiveMatch = /^receive\b/i.exec(trimmed);
  const fallbackMatch = /^fallback\b/i.exec(trimmed);

  if (fnMatch) {
    afterKeywordIdx = fnMatch[0].length;
    const nameMatch = /^\s*([A-Za-z_$][\w$]*)/.exec(trimmed.slice(afterKeywordIdx));
    name = nameMatch ? nameMatch[1]! : 'fallback'; // anonymous pre-0.6 fallback: `function() external {}`
  } else if (ctorMatch) {
    afterKeywordIdx = ctorMatch[0].length;
    name = 'constructor';
    isConstructor = true;
  } else if (receiveMatch) {
    afterKeywordIdx = receiveMatch[0].length;
    name = 'receive';
  } else if (fallbackMatch) {
    afterKeywordIdx = fallbackMatch[0].length;
    name = 'fallback';
  } else {
    return null;
  }

  const openParen = trimmed.indexOf('(', afterKeywordIdx);
  if (openParen === -1) return null;
  const closeParen = findMatchingParen(trimmed, openParen);
  if (closeParen === -1) return null;

  const parametersRaw = trimmed.slice(openParen + 1, closeParen);
  const tail = trimmed.slice(closeParen + 1);
  const tokens = tokenizeTail(tail);

  let visibility: Visibility | undefined;
  let stateMutability: StateMutability | undefined;
  const modifiers: string[] = [];
  for (const tok of tokens) {
    if (VISIBILITY_KEYWORDS.has(tok as Visibility)) {
      visibility = tok as Visibility;
    } else if (MUTABILITY_KEYWORDS.has(tok as StateMutability)) {
      stateMutability = tok as StateMutability;
    } else if (IGNORED_HEADER_TOKENS.has(tok)) {
      // virtual/override: not access-control-relevant, discard.
    } else {
      modifiers.push(tok);
    }
  }

  return { name, isConstructor, visibility, stateMutability, modifiers, parametersRaw };
}

const DATA_LOCATION_KEYWORDS = new Set(['memory', 'storage', 'calldata', 'indexed', 'payable']);

/**
 * Split a parameter list into `{ name, type }` pairs. Unnamed parameters
 * (`function f(uint256)`) are omitted entirely, matching the long-standing
 * `parameters` semantics. The type is every token before the name with data
 * locations dropped, re-joined with single spaces — good enough to answer
 * "is this an address?" / "is this an IERC20?" without a type checker.
 */
function parseParameters(parametersRaw: string): ParameterInfo[] {
  if (parametersRaw.trim() === '') return [];
  const chunks = splitTopLevel(parametersRaw, ',');
  const params: ParameterInfo[] = [];
  for (const chunk of chunks) {
    const tokens = chunk.trim().split(/\s+/).filter(Boolean);
    if (tokens.length < 2) continue;
    const last = tokens[tokens.length - 1]!;
    if (!/^[A-Za-z_$][\w$]*$/.test(last)) continue;
    const type = tokens
      .slice(0, -1)
      .filter((t) => !DATA_LOCATION_KEYWORDS.has(t))
      .join(' ');
    params.push({ name: last, type });
  }
  return params;
}

/**
 * Base contract names from a `contract A is B, C(1)` header. Returns [] when
 * there is no `is` clause. Constructor arguments are dropped; only the
 * leading identifier of each comma-separated entry is kept.
 */
function parseBaseNames(header: string, nameEndIndex: number): string[] {
  const tail = header.slice(nameEndIndex);
  const isMatch = /^\s*\bis\b/.exec(tail);
  if (!isMatch) return [];
  const listText = tail.slice(isMatch[0].length);
  const names: string[] = [];
  for (const chunk of splitTopLevel(listText, ',')) {
    const m = /^\s*([A-Za-z_$][\w$]*)/.exec(chunk);
    if (m) names.push(m[1]!);
  }
  return names;
}

function findTopLevelAssignEquals(text: string): number {
  // Excludes ==, !=, <=, >= (comparisons) AND => (the mapping type arrow,
  // e.g. `mapping(address => uint256)`) — none of those are an initializer.
  const m = /(?<![=!<>])=(?![=>])/.exec(text);
  return m ? m.index : -1;
}

function tryExtractStateVar(buf: string, startLine: number, contract: ContractInfo): void {
  const trimmed = buf.trim();
  if (trimmed === '') return;
  if (EXCLUDED_STATEMENT_START_RE.test(trimmed)) return;

  const eqIdx = findTopLevelAssignEquals(trimmed);
  const declPart = eqIdx === -1 ? trimmed : trimmed.slice(0, eqIdx);
  const tokens = declPart.trim().split(/\s+/).filter(Boolean);
  if (tokens.length < 2) return;

  const name = tokens[tokens.length - 1]!.replace(/[[\]]/g, '');
  if (!/^[A-Za-z_$][\w$]*$/.test(name)) return;

  const isConstantOrImmutable = /\b(constant|immutable)\b/.test(declPart);
  // Leading token of the declaration: `IERC20 public token` -> `IERC20`.
  // `mapping(address => uint256) public m` collapses to `mapping(address`
  // under a whitespace split, so take only up to the first '(' as well.
  const declaredType = (tokens[0] ?? '').split('(')[0] ?? '';
  contract.stateVariables.push({ name, line: startLine, isConstantOrImmutable, declaredType });
}

export function parseSolidityFile(relPath: string, source: string): ParsedSolidityFile {
  const lines = stripCommentsAndStrings(source);
  const pragmas = extractPragmas(lines);
  const defaultVisibility = defaultVisibilityFor(pragmas);
  const warnings: string[] = [];
  const contracts: ContractInfo[] = [];

  const stack: Frame[] = [];
  let depth = 0;
  let currentFunctionFrame: FunctionFrame | null = null;
  let currentModifierFrame: ModifierFrame | null = null;

  let stmtBuf = '';
  let stmtStartLine = -1;

  const resetStmt = (): void => {
    stmtBuf = '';
    stmtStartLine = -1;
  };

  const currentContractFrame = (): ContractFrame | undefined => {
    const top = stack[stack.length - 1];
    return isContractFrame(top) ? top : undefined;
  };

  // Returns the new frame (or null on a malformed header) instead of
  // assigning `currentFunctionFrame` itself: TypeScript's control-flow
  // narrowing does not see through a nested closure's assignment to an
  // outer `let`, so hiding the assignment in here previously made every
  // `if (currentFunctionFrame)` check downstream look statically
  // unreachable. Assigning at the call site keeps it visible to CFA.
  const openFunctionFrame = (
    headerText: string,
    headerLine: number,
    atLineObj: SourceLine,
  ): FunctionFrame | null => {
    const parsed = parseHeader(headerText);
    if (!parsed) {
      // Couldn't make sense of the header (malformed/truncated); keep depth
      // bookkeeping sound by pushing a generic frame instead of crashing.
      warnings.push(`${relPath}:${headerLine}: could not parse function header, skipping`);
      stack.push({ kind: 'other', depth: depth + 1 });
      return null;
    }
    const visibility = parsed.visibility ?? defaultVisibility;
    const stateMutability = parsed.stateMutability ?? 'nonpayable';
    const declaredParameters = parseParameters(parsed.parametersRaw);
    const info: FunctionInfo = {
      name: parsed.name,
      isConstructor: parsed.isConstructor,
      visibility,
      stateMutability,
      modifiers: parsed.modifiers,
      parameters: declaredParameters.map((p) => p.name),
      declaredParameters,
      headerLine,
      hasBody: true,
      bodyStartLine: atLineObj.line,
      body: [{ line: atLineObj.line, original: atLineObj.original, stripped: atLineObj.stripped }],
    };
    const frame: FunctionFrame = { kind: 'function', depth: depth + 1, info };
    stack.push(frame);
    return frame;
  };

  // Same "return the frame rather than assigning an outer `let`" shape as
  // openFunctionFrame above, for the same control-flow-narrowing reason.
  const openModifierFrame = (
    headerText: string,
    headerLine: number,
    atLineObj: SourceLine,
  ): ModifierFrame | null => {
    const nameMatch = /^\s*modifier\s+([A-Za-z_$][\w$]*)/i.exec(headerText);
    if (!nameMatch) {
      warnings.push(`${relPath}:${headerLine}: could not parse modifier header, skipping`);
      stack.push({ kind: 'other', depth: depth + 1 });
      return null;
    }
    const openParen = headerText.indexOf('(', nameMatch[0].length);
    let parameters: string[] = [];
    if (openParen !== -1) {
      const closeParen = findMatchingParen(headerText, openParen);
      if (closeParen !== -1) {
        parameters = parseParameters(headerText.slice(openParen + 1, closeParen)).map(
          (p) => p.name,
        );
      }
    }
    const info: ModifierInfo = {
      name: nameMatch[1]!,
      parameters,
      headerLine,
      hasBody: true,
      bodyStartLine: atLineObj.line,
      body: [{ line: atLineObj.line, original: atLineObj.original, stripped: atLineObj.stripped }],
    };
    const frame: ModifierFrame = { kind: 'modifier', depth: depth + 1, info };
    stack.push(frame);
    return frame;
  };

  for (const lineObj of lines) {
    if (currentFunctionFrame) {
      currentFunctionFrame.info.body.push({
        line: lineObj.line,
        original: lineObj.original,
        stripped: lineObj.stripped,
      });
    }
    if (currentModifierFrame) {
      currentModifierFrame.info.body.push({
        line: lineObj.line,
        original: lineObj.original,
        stripped: lineObj.stripped,
      });
    }

    const text = lineObj.stripped;
    for (let col = 0; col < text.length; col++) {
      const ch = text.charAt(col);

      if (ch === '{') {
        const header = stmtBuf;
        const headerLine = stmtStartLine === -1 ? lineObj.line : stmtStartLine;

        if (depth === 0 && !currentContractFrame()) {
          const m = CONTRACT_OPEN_RE.exec(header);
          if (m) {
            const keyword = m[1]!.trim();
            const kind: ContractKind = keyword.startsWith('abstract')
              ? 'abstract'
              : (keyword as ContractKind);
            const info: ContractInfo = {
              name: m[2]!,
              kind,
              startLine: headerLine,
              endLine: headerLine,
              stateVariables: [],
              functions: [],
              modifierNames: [],
              modifiers: [],
              baseNames: parseBaseNames(header, m.index + m[0].length),
            };
            stack.push({ kind, depth: depth + 1, info } as ContractFrame);
            depth++;
            resetStmt();
            continue;
          }
          stack.push({ kind: 'other', depth: depth + 1 });
          depth++;
          resetStmt();
          continue;
        }

        const contractFrame = currentContractFrame();
        if (contractFrame && contractFrame.depth === depth) {
          const trimmedHeader = header.trim();
          if (/^modifier\b/i.test(trimmedHeader)) {
            currentModifierFrame = openModifierFrame(trimmedHeader, headerLine, lineObj);
            if (currentModifierFrame) {
              contractFrame.info.modifierNames.push(currentModifierFrame.info.name);
            }
            depth++;
            resetStmt();
            continue;
          }
          if (/^(function|constructor|receive|fallback)\b/i.test(trimmedHeader)) {
            currentFunctionFrame = openFunctionFrame(header, headerLine, lineObj);
            depth++;
            resetStmt();
            continue;
          }
        }

        stack.push({ kind: 'other', depth: depth + 1 });
        depth++;
        resetStmt();
        continue;
      }

      if (ch === '}') {
        const top = stack[stack.length - 1];
        if (top && top.depth === depth) {
          stack.pop();
          if (top.kind === 'function') {
            const fn = (top as FunctionFrame).info;
            fn.bodyEndLine = lineObj.line;
            currentFunctionFrame = null;
            const owner = currentContractFrame();
            owner?.info.functions.push(fn);
          } else if (top.kind === 'modifier') {
            // Only openModifierFrame pushes a 'modifier' frame, and only on a
            // successfully parsed header, so `info` is always present here.
            const mod = (top as ModifierFrame).info;
            mod.bodyEndLine = lineObj.line;
            currentModifierFrame = null;
            const owner = currentContractFrame();
            owner?.info.modifiers.push(mod);
          } else if (isContractFrame(top)) {
            top.info.endLine = lineObj.line;
            contracts.push(top.info);
          }
        } else if (depth === 0) {
          warnings.push(`${relPath}:${lineObj.line}: unexpected '}' with no open block, ignoring`);
        }
        depth = Math.max(0, depth - 1);
        resetStmt();
        continue;
      }

      if (ch === ';') {
        const contractFrame = currentContractFrame();
        if (contractFrame && contractFrame.depth === depth) {
          const header = stmtBuf.trim();
          if (/^(function|constructor|receive|fallback)\b/i.test(header)) {
            const parsed = parseHeader(stmtBuf);
            if (parsed) {
              const visibility = parsed.visibility ?? defaultVisibility;
              const stateMutability = parsed.stateMutability ?? 'nonpayable';
              const declaredParameters = parseParameters(parsed.parametersRaw);
              contractFrame.info.functions.push({
                name: parsed.name,
                isConstructor: parsed.isConstructor,
                visibility,
                stateMutability,
                modifiers: parsed.modifiers,
                parameters: declaredParameters.map((p) => p.name),
                declaredParameters,
                headerLine: stmtStartLine === -1 ? lineObj.line : stmtStartLine,
                hasBody: false,
                body: [],
              });
            } else {
              warnings.push(
                `${relPath}:${lineObj.line}: could not parse function declaration, skipping`,
              );
            }
          } else if (/^modifier\b/i.test(header)) {
            // `modifier X() virtual;` in an abstract contract: declared but
            // unimplemented. Recorded body-less so guard analysis reports it
            // as unresolvable rather than "provably not a guard".
            const nameMatch = /^modifier\s+([A-Za-z_$][\w$]*)/i.exec(header);
            if (nameMatch) {
              contractFrame.info.modifierNames.push(nameMatch[1]!);
              contractFrame.info.modifiers.push({
                name: nameMatch[1]!,
                parameters: [],
                headerLine: stmtStartLine === -1 ? lineObj.line : stmtStartLine,
                hasBody: false,
                body: [],
              });
            }
          } else {
            tryExtractStateVar(
              stmtBuf,
              stmtStartLine === -1 ? lineObj.line : stmtStartLine,
              contractFrame.info,
            );
          }
        }
        resetStmt();
        continue;
      }

      if (stmtStartLine === -1 && !/\s/.test(ch)) {
        stmtStartLine = lineObj.line;
      }
      stmtBuf += ch;
    }
    // Newline boundary: keep accumulating (multi-line statements/headers are
    // valid) but normalize to a single space so tokens across lines don't glue.
    if (stmtBuf.length > 0) stmtBuf += ' ';
  }

  if (stack.length > 0) {
    warnings.push(`${relPath}: reached end of file with ${stack.length} unclosed block(s)`);
    const lastLine = lines[lines.length - 1]?.line ?? 1;
    // Best-effort: close out any still-open frames using EOF as their end, so
    // a truncated file still yields partial, usable results instead of none.
    for (const frame of stack) {
      if (frame.kind === 'function') {
        (frame as FunctionFrame).info.bodyEndLine = lastLine;
      } else if (frame.kind === 'modifier') {
        (frame as ModifierFrame).info.bodyEndLine = lastLine;
      } else if (isContractFrame(frame)) {
        frame.info.endLine = lastLine;
      }
    }
    // Outermost first, so a contract frame is already in `contracts` (by
    // reference) by the time we look for it as a function/modifier frame's
    // parent.
    const enclosingContract = (index: number): ContractFrame | undefined => {
      for (let j = index - 1; j >= 0; j--) {
        const candidate = stack[j]!;
        if (isContractFrame(candidate)) return candidate;
      }
      return undefined;
    };
    for (let i = 0; i < stack.length; i++) {
      const frame = stack[i]!;
      if (frame.kind === 'function') {
        enclosingContract(i)?.info.functions.push((frame as FunctionFrame).info);
      } else if (frame.kind === 'modifier') {
        enclosingContract(i)?.info.modifiers.push((frame as ModifierFrame).info);
      } else if (isContractFrame(frame)) {
        contracts.push(frame.info);
      }
    }
  }

  return { relPath, lines, pragmas, contracts, warnings };
}
