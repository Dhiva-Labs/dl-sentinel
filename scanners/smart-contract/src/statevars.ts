/**
 * Detects writes to known state variables within a single (stripped) source
 * line. Shared by SC001 (reentrancy: any write) and SC008 (pre-0.8 unchecked
 * arithmetic: specifically arithmetic writes).
 *
 * Heuristic limits: this is line-based, so a write that occurs earlier on
 * the same physical line as an external call (or vice versa) is not ordered
 * relative to it — see SC001's own doc comment. Multi-statement-per-line
 * source is rare in formatted Solidity, so this trades a small amount of
 * recall for a much simpler, more auditable implementation.
 */

import { escapeRegExp } from './util.js';

export interface StateWriteMatch {
  name: string;
  isCompound: boolean;
  isDelete: boolean;
  /** Text after a plain '=' (undefined for compound-assignment/delete forms). */
  rhs?: string;
}

/** Optional `[index]` / `.field` accessors between the variable name and the operator. */
const ACCESSOR_SUFFIX = String.raw`(?:\[[^\]]*\]|\.[A-Za-z_$][\w$]*)*`;

/**
 * Find the first known state variable that `line` writes to (assignment,
 * compound assignment, or `delete`). Checks variable names in the order
 * given; returns the first hit.
 */
export function findStateWrite(
  line: string,
  stateVarNames: readonly string[],
): StateWriteMatch | null {
  for (const name of stateVarNames) {
    const escaped = escapeRegExp(name);
    const boundaryPrefix = `(?:^|[^.\\w$])`;

    const compoundRe = new RegExp(
      `${boundaryPrefix}${escaped}\\s*${ACCESSOR_SUFFIX}\\s*(\\+=|-=|\\*=|/=|%=|\\|=|&=|\\^=|<<=|>>=)`,
    );
    if (compoundRe.test(line)) {
      return { name, isCompound: true, isDelete: false };
    }

    const deleteRe = new RegExp(`\\bdelete\\s+${escaped}\\b`);
    if (deleteRe.test(line)) {
      return { name, isCompound: false, isDelete: true };
    }

    const plainRe = new RegExp(
      `${boundaryPrefix}${escaped}\\s*${ACCESSOR_SUFFIX}\\s*=(?![=>])([^;]*)`,
    );
    const plainMatch = plainRe.exec(line);
    if (plainMatch) {
      return { name, isCompound: false, isDelete: false, rhs: plainMatch[1] ?? '' };
    }
  }
  return null;
}

/**
 * True if `line` writes to `name` using specifically `+=`, `-=`, or `*=` —
 * the compound-assignment forms that can overflow/underflow pre-0.8.
 * `/=` and `%=` truncate but cannot overflow; bitwise compounds are unrelated.
 */
export function isArithmeticCompoundOp(line: string, name: string): boolean {
  const escaped = escapeRegExp(name);
  const re = new RegExp(`(?:^|[^.\\w$])${escaped}\\s*${ACCESSOR_SUFFIX}\\s*(\\+=|-=|\\*=)`);
  return re.test(line);
}

/**
 * True if `expr` contains a binary `+`, `-`, or `*` that is not part of a
 * doubled operator (`++`, `--`, `**`) — i.e. looks like real arithmetic
 * rather than increment/decrement or exponentiation.
 */
export function hasBinaryArithmetic(expr: string): boolean {
  return /(?<![+\-*])[+\-*](?![+\-*])/.test(expr);
}
