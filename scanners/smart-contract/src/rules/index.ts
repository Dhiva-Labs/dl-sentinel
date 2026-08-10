import { sc001Reentrancy } from './sc001-reentrancy.js';
import { sc002TxOrigin } from './sc002-tx-origin.js';
import { sc003UncheckedCall } from './sc003-unchecked-call.js';
import { sc004Delegatecall } from './sc004-delegatecall.js';
import { sc005Selfdestruct } from './sc005-selfdestruct.js';
import { sc006Initializer } from './sc006-initializer.js';
import { sc007Mint } from './sc007-mint.js';
import { sc008UncheckedArithmetic } from './sc008-unchecked-arithmetic.js';
import { sc009Pragma } from './sc009-pragma.js';
import { sc010Randomness } from './sc010-randomness.js';
import { sc011Deprecated } from './sc011-deprecated.js';
import { sc012SetterEvents } from './sc012-setter-events.js';
import type { RuleDefinition } from './types.js';

export const allRules: readonly RuleDefinition[] = [
  sc001Reentrancy,
  sc002TxOrigin,
  sc003UncheckedCall,
  sc004Delegatecall,
  sc005Selfdestruct,
  sc006Initializer,
  sc007Mint,
  sc008UncheckedArithmetic,
  sc009Pragma,
  sc010Randomness,
  sc011Deprecated,
  sc012SetterEvents,
];

export type { RuleContext, RuleDefinition } from './types.js';
export {
  sc001Reentrancy,
  sc002TxOrigin,
  sc003UncheckedCall,
  sc004Delegatecall,
  sc005Selfdestruct,
  sc006Initializer,
  sc007Mint,
  sc008UncheckedArithmetic,
  sc009Pragma,
  sc010Randomness,
  sc011Deprecated,
  sc012SetterEvents,
};
