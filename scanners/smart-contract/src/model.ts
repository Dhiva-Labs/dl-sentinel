/**
 * Internal parse model for the smart-contract scanner.
 *
 * This is NOT the `Finding`/`RuleMeta` model from `@dl-sentinel/core` — it is
 * the scanner's own lightweight representation of a `.sol` file, produced by
 * `parser.ts` and consumed by `rules/*`. It intentionally captures only what
 * the rule catalog (SC001-SC012) needs; it is not a full Solidity AST.
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
