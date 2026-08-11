/**
 * Internal parse model for the smart-contract scanner.
 *
 * This is NOT the `Finding`/`RuleMeta` model from `@dl-sentinel/core` — it is
 * the scanner's own lightweight representation of a `.sol` file, produced by
 * `parser.ts` and consumed by `rules/*`. It intentionally captures only what
 * the rule catalog (SC001-SC017) needs; it is not a full Solidity AST.
 *
 * `resolve.ts` layers a *contract-level* view on top of this raw parse:
 * same-file inheritance resolution, modifier bodies, and an intra-file call
 * graph. Anything in this file is what a single pass over the text recovered;
 * anything in `resolve.ts` is what cross-referencing those parses inferred.
 */

export type Visibility = 'public' | 'external' | 'internal' | 'private';

export type StateMutability = 'payable' | 'view' | 'pure' | 'nonpayable';

export type ContractKind = 'contract' | 'interface' | 'library' | 'abstract';

/** One physical source line, kept in both its original and stripped forms. */
export interface SourceLine {
  /** 1-based line number in the original file. */
  line: number;
  /** Original source text (used for evidence — never for pattern matching). */
  original: string;
  /**
   * Comment- and string-literal-stripped text (same length/line count as the
   * original; stripped spans are replaced with spaces). Rules match against
   * this, never against `original`, so a pattern name mentioned in a comment
   * or string can never trigger a finding.
   */
  stripped: string;
}

/** One declared parameter: its name plus the declared type text preceding it. */
export interface ParameterInfo {
  name: string;
  /**
   * Declared type as written, with data-location keywords (`memory`,
   * `storage`, `calldata`) and `indexed` removed — e.g. `address`,
   * `uint256`, `IERC20`, `bytes`.
   */
  type: string;
}

export interface FunctionInfo {
  /** Function name; `constructor`/`receive`/`fallback` for those special functions. */
  name: string;
  isConstructor: boolean;
  visibility: Visibility;
  stateMutability: StateMutability;
  /** Modifier names as applied on the function signature, in source order. */
  modifiers: string[];
  /** Parameter names the header parser could recover (unnamed params are omitted). */
  parameters: string[];
  /**
   * Same parameters as `parameters`, in the same order, carrying their
   * declared type text as well. Kept alongside (rather than replacing)
   * `parameters` so the name-only consumers stay untouched.
   */
  declaredParameters: ParameterInfo[];
  /** Line of the `function`/`constructor`/`receive`/`fallback` keyword. */
  headerLine: number;
  /**
   * False for a body-less declaration (interface method, or an unimplemented
   * `virtual` function in an abstract contract) — the header ends in `;`.
   */
  hasBody: boolean;
  bodyStartLine?: number;
  bodyEndLine?: number;
  /**
   * Every physical line the function's `{ ... }` spans (including the lines
   * holding the opening/closing braces themselves), in order. Empty when
   * `hasBody` is false.
   */
  body: SourceLine[];
}

export interface StateVariableInfo {
  name: string;
  /** Line where the declaration statement starts. */
  line: number;
  isConstantOrImmutable: boolean;
  /**
   * Leading type token of the declaration as written (`address`, `uint256`,
   * `IERC20`, `mapping`, ...). Empty when the declaration was too malformed
   * to recover one.
   */
  declaredType: string;
}

/** A `modifier X(...) { ... }` declaration, including its body. */
export interface ModifierInfo {
  name: string;
  /** Parameter names the header parser could recover. */
  parameters: string[];
  /** Line of the `modifier` keyword. */
  headerLine: number;
  /**
   * False for a body-less `modifier X() virtual;` declaration in an abstract
   * contract — the guard it enforces lives in whichever contract overrides it.
   */
  hasBody: boolean;
  bodyStartLine?: number;
  bodyEndLine?: number;
  /** Every physical line the modifier's `{ ... }` spans, in order. */
  body: SourceLine[];
}

export interface ContractInfo {
  name: string;
  kind: ContractKind;
  startLine: number;
  endLine: number;
  /** Top-level (non-function-local) variable declarations. */
  stateVariables: StateVariableInfo[];
  functions: FunctionInfo[];
  /** Names of modifiers declared with `modifier X(...) { ... }` in this contract. */
  modifierNames: string[];
  /** Full declarations (with bodies) of this contract's own modifiers. */
  modifiers: ModifierInfo[];
  /**
   * Base contract names from `contract A is B, C`, in source (left-to-right)
   * order, with any constructor arguments stripped (`is Owned(msg.sender)`
   * yields `Owned`). A base declared in another file is still listed here —
   * `resolve.ts` reports it as unresolved rather than dropping it.
   */
  baseNames: string[];
}

export interface PragmaInfo {
  /** The raw version constraint, e.g. "^0.8.0" or ">=0.7.0 <0.9.0". */
  raw: string;
  /** Line of the `pragma solidity ...;` statement. */
  line: number;
  /** Full original statement text, for evidence. */
  fullStatement: string;
}

export interface ParsedSolidityFile {
  relPath: string;
  /** Every physical line of the file (original + stripped), 0-indexed by line-1. */
  lines: readonly SourceLine[];
  pragmas: PragmaInfo[];
  contracts: ContractInfo[];
  /** Non-fatal issues encountered while parsing; the parser never throws for these. */
  warnings: string[];
}
