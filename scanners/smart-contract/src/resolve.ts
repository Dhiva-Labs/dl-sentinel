/**
 * Contract-level resolution: same-file inheritance, an effective member view,
 * and an intra-file call graph.
 *
 * `parser.ts` recovers what a single text pass can see inside one contract
 * body. This module cross-references those parses so a rule can ask
 * contract-level questions — "is this function's modifier defined in a base?",
 * "what does this function call?" — that no per-function line heuristic can
 * answer.
 *
 * Documented heuristic limits (all deliberate; this is not a compiler):
 *
 * 1. **Same file only.** A base contract declared in another file (an
 *    `import`) cannot be resolved — the scanner never reads beyond the file it
 *    was handed. Such bases are listed in `unknownBaseNames`, and members
 *    inherited from them are simply absent from the effective view. Rules must
 *    treat "not found" as "unknown", never as "does not exist" (see
 *    `guards.ts`, which maps an unresolvable modifier to "assume protected").
 *
 * 2. **Linearization is most-derived-wins, left-to-right, not C3.** The chain
 *    is a pre-order depth-first walk: the contract itself, then its first base
 *    and that base's own bases, then its second base, and so on. The contract
 *    itself always wins over any base, which is the part that matters for
 *    override semantics. Where real Solidity differs is tie-breaking *between*
 *    bases: C3 linearization resolves `contract C is A, B` right-to-left (B
 *    overrides A), while this walk takes A first. That only changes the answer
 *    when two bases declare the same member name AND the derived contract does
 *    not itself override it — rare in practice, and never in a direction that
 *    invents a member that isn't there.
 *
 * 3. **Overloads resolve by name only.** `transfer(address,uint256)` and
 *    `transfer(address,uint256,bytes)` collapse to one entry keyed `transfer`;
 *    the first declaration in linearization order wins. Arity/type-based
 *    dispatch would need a type checker.
 *
 * 4. **Call edges are name matches, not bindings.** A call edge is recorded
 *    when an identifier followed by `(` matches a known function name and is
 *    not preceded by `.`. That deliberately excludes `token.transfer(...)`
 *    (an external call on another contract) and `this.f()` / `super.f()`
 *    (which are external / base-dispatched rather than a plain internal hop).
 *    A local variable shadowing a function name, or a function pointer, is not
 *    tracked.
 *
 * Results are memoized per `ParsedSolidityFile` object identity, so the
 * catalog's rules share one resolution pass per file. Resolution is a pure
 * function of the parse, so this never affects determinism.
 */

import type {
  ContractInfo,
  FunctionInfo,
  ModifierInfo,
  ParsedSolidityFile,
  SourceLine,
  StateVariableInfo,
} from './model.js';

/** Guard against a pathological (or cyclic) inheritance graph in malformed input. */
const MAX_LINEARIZATION_DEPTH = 16;

export interface ResolvedFunction {
  /** Contract whose body declares this function (may be a base of the subject). */
  declaringContract: ContractInfo;
  fn: FunctionInfo;
  /** True when the declaration came from a base rather than the subject contract. */
  inherited: boolean;
}

export interface ResolvedModifier {
  declaringContract: ContractInfo;
  modifier: ModifierInfo;
  inherited: boolean;
}

export interface ResolvedContract {
  info: ContractInfo;
  /** `[self, ...bases]`, pre-order depth-first, most-derived first (see limit 2). */
  linearization: readonly ContractInfo[];
  /**
   * Base names referenced anywhere in the linearization that this file does
   * not declare — almost always imports. Their members are unresolvable.
   */
  unknownBaseNames: readonly string[];
  /** Effective functions keyed by name; earliest in linearization order wins. */
  functions: ReadonlyMap<string, ResolvedFunction>;
  /** Effective modifiers keyed by name; earliest in linearization order wins. */
  modifiers: ReadonlyMap<string, ResolvedModifier>;
  /** Own + inherited state variables, most-derived first, de-duplicated by name. */
  stateVariables: readonly StateVariableInfo[];
  /** Convenience projection of `stateVariables` used by the write detectors. */
  stateVariableNames: readonly string[];
  /**
   * Intra-file call graph: function name -> names of resolved functions it
   * calls, unique and sorted for determinism. Keys cover every function in
   * `functions` (a function that calls nothing maps to an empty array).
   */
  callGraph: ReadonlyMap<string, readonly string[]>;
}

export interface ResolvedFile {
  file: ParsedSolidityFile;
  /** Keyed by contract name; one entry per contract/interface/library declared. */
  contracts: ReadonlyMap<string, ResolvedContract>;
}

/** One place a function calls another in-contract function. */
export interface CallSite {
  /** Index into the caller's `body` array (not a line number). */
  bodyIndex: number;
  /** Resolved callee function name. */
  callee: string;
}

const CALL_RE = /(?<![.\w$])([A-Za-z_$][\w$]*)\s*\(/g;

/**
 * A function's or modifier's body with the *declaration header* blanked out.
 *
 * `body[0]` is the line carrying the opening `{`, which for the usual
 * single-line header also carries `function withdraw(uint256 amount) external
 * onlyOwner`. Scanning that text as if it were a statement is wrong in two
 * ways that both cause false "proof": `withdraw(` reads as a self-call, and
 * `modifier onlyOwner()` reads as a call to an authorization helper — so an
 * empty `modifier onlyOwner() { _; }` would prove itself a guard by its own
 * name. Everything up to and including the first `{` is replaced with spaces
 * (not removed) so column positions and array indices stay aligned with the
 * original body.
 */
export function statementLines(body: readonly SourceLine[]): SourceLine[] {
  if (body.length === 0) return [];
  const first = body[0]!;
  const brace = first.stripped.indexOf('{');
  const stripped =
    brace === -1
      ? ' '.repeat(first.stripped.length)
      : ' '.repeat(brace + 1) + first.stripped.slice(brace + 1);
  return [{ line: first.line, original: first.original, stripped }, ...body.slice(1)];
}

/**
 * Find every call from `body` to a name in `knownNames`, in body order.
 * Duplicate call sites (same line, same callee) collapse to one entry.
 */
export function findCallSites(
  body: readonly SourceLine[],
  knownNames: ReadonlySet<string>,
): CallSite[] {
  const sites: CallSite[] = [];
  const lines = statementLines(body);
  for (let i = 0; i < lines.length; i++) {
    const text = lines[i]!.stripped;
    if (text.trim() === '') continue;
    const re = new RegExp(CALL_RE.source, 'g');
    const seenOnLine = new Set<string>();
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const name = m[1]!;
      if (!knownNames.has(name) || seenOnLine.has(name)) continue;
      seenOnLine.add(name);
      sites.push({ bodyIndex: i, callee: name });
    }
  }
  return sites;
}

function linearize(
  root: ContractInfo,
  byName: ReadonlyMap<string, ContractInfo>,
): { chain: ContractInfo[]; unknown: string[] } {
  const chain: ContractInfo[] = [];
  const seen = new Set<string>();
  const unknown: string[] = [];

  const visit = (contract: ContractInfo, depth: number): void => {
    if (depth > MAX_LINEARIZATION_DEPTH) return;
    if (seen.has(contract.name)) return;
    seen.add(contract.name);
    chain.push(contract);
    for (const baseName of contract.baseNames) {
      const base = byName.get(baseName);
      if (base) {
        visit(base, depth + 1);
      } else if (!unknown.includes(baseName)) {
        unknown.push(baseName);
      }
    }
  };

  visit(root, 0);
  return { chain, unknown };
}

function resolveContract(
  info: ContractInfo,
  byName: ReadonlyMap<string, ContractInfo>,
): ResolvedContract {
  const { chain, unknown } = linearize(info, byName);

  const functions = new Map<string, ResolvedFunction>();
  const modifiers = new Map<string, ResolvedModifier>();
  const stateVariables: StateVariableInfo[] = [];
  const seenStateVars = new Set<string>();

  for (const contract of chain) {
    const inherited = contract !== info;
    for (const fn of contract.functions) {
      if (fn.isConstructor) continue; // constructors are never inherited or called by name
      if (!functions.has(fn.name)) {
        functions.set(fn.name, { declaringContract: contract, fn, inherited });
      }
    }
    for (const modifier of contract.modifiers) {
      if (!modifiers.has(modifier.name)) {
        modifiers.set(modifier.name, { declaringContract: contract, modifier, inherited });
      }
    }
    for (const variable of contract.stateVariables) {
      if (seenStateVars.has(variable.name)) continue;
      seenStateVars.add(variable.name);
      stateVariables.push(variable);
    }
  }

  const knownNames = new Set(functions.keys());
  const callGraph = new Map<string, readonly string[]>();
  for (const [name, resolved] of functions) {
    if (!resolved.fn.hasBody) {
      callGraph.set(name, []);
      continue;
    }
    const callees = new Set(findCallSites(resolved.fn.body, knownNames).map((s) => s.callee));
    callees.delete(name); // self-recursion adds no reachability
    callGraph.set(name, [...callees].sort());
  }

  return {
    info,
    linearization: chain,
    unknownBaseNames: unknown,
    functions,
    modifiers,
    stateVariables,
    stateVariableNames: stateVariables.map((v) => v.name),
    callGraph,
  };
}

const cache = new WeakMap<ParsedSolidityFile, ResolvedFile>();

/**
 * Resolve every contract in a parsed file. Memoized on the parse object, so
 * all rules in one scan share a single resolution pass per file.
 */
export function resolveFile(file: ParsedSolidityFile): ResolvedFile {
  const cached = cache.get(file);
  if (cached) return cached;

  const byName = new Map<string, ContractInfo>();
  for (const contract of file.contracts) {
    // First declaration wins; duplicate names are invalid Solidity, but
    // malformed input must still resolve deterministically.
    if (!byName.has(contract.name)) byName.set(contract.name, contract);
  }

  const contracts = new Map<string, ResolvedContract>();
  for (const contract of file.contracts) {
    if (!contracts.has(contract.name))
      contracts.set(contract.name, resolveContract(contract, byName));
  }

  const resolved: ResolvedFile = { file, contracts };
  cache.set(file, resolved);
  return resolved;
}

/** The resolved view of one contract from an already-parsed file. */
export function resolveContractIn(
  file: ParsedSolidityFile,
  contract: ContractInfo,
): ResolvedContract {
  const resolvedFile = resolveFile(file);
  return resolvedFile.contracts.get(contract.name) ?? resolveContract(contract, new Map());
}

/**
 * Names of every function reachable from `entry` through in-contract calls,
 * up to `maxDepth` hops (`entry` itself is not included). Cycle-safe.
 */
export function reachableFunctions(
  resolved: ResolvedContract,
  entry: string,
  maxDepth: number,
): Set<string> {
  const out = new Set<string>();
  if (maxDepth < 1) return out;

  let frontier = [entry];
  const visited = new Set<string>([entry]);
  for (let depth = 0; depth < maxDepth && frontier.length > 0; depth++) {
    const next: string[] = [];
    for (const name of frontier) {
      for (const callee of resolved.callGraph.get(name) ?? []) {
        if (visited.has(callee)) continue;
        visited.add(callee);
        out.add(callee);
        next.push(callee);
      }
    }
    frontier = next;
  }
  return out;
}
