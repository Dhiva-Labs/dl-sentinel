# Rules

This page covers the rule-id namespace scheme, what severity and confidence mean, how `sentinel
rules` is expected to list rules, and how to author a new rule. It is not a catalog of specific
rules — see [Scanners](scanners.md) for what each scanner area covers at a contract level, and
consult a scanner's own `rules: RuleMeta[]` array (once implemented) for the definitive list it
ships.

## Rule id namespaces

Every rule id is a namespace prefix followed by a zero-padded number, for example `S001`. The
prefix identifies the producing scanner:

| Prefix | Scanner | Example |
| --- | --- | --- |
| `S` | secrets | `S001` |
| `D` | dependencies | `D001` |
| `C` | source code | `C001` |
| `I` | infra/docker | `I001` |
| `A` | api | `A001` |
| `SC` | smart-contract | `SC001` |

The "Example" column shows the id *format*, not a claim that these specific rules exist — no
scanner has shipped a rule catalog yet (see [Scanners](scanners.md)). The one concrete id in the
codebase today is `S001` ("Hardcoded credential detected"), used as the illustrative example in
[Scanner interface](scanner-interface.md#skeleton) and [Finding schema](finding-schema.md).

The `Finding.category` enum in `packages/core/src/types.ts` additionally includes `config` and
`other`, which do not map to a rule-id prefix above; they exist for findings outside the six
scanner areas.

## Severity

Severity is impact, defined in [Finding schema](finding-schema.md#severity-definitions):

- **critical** — exploitable now with severe impact (live credential, RCE-equivalent pattern,
  contract fund-drain risk).
- **high** — serious weakness likely exploitable (known-vulnerable dependency in use, SQL
  injection pattern, privileged container).
- **medium** — weakness needing specific conditions (weak crypto, missing TLS verification,
  permissive CORS).
- **low** — hardening gap or hygiene issue (missing resource limits, unpinned image).
- **info** — observation, no direct risk (scanner skipped something, inventory notes).

## Confidence

Confidence is detection certainty, independent of severity:

- **high** — the pattern is unambiguous (structured token format matched, lockfile version
  exactly in a vulnerable range).
- **medium** — the pattern is strong but context could legitimize it.
- **low** — heuristic (entropy-only match, name-based hint). Low-confidence rules should be
  conservative in the severity they assign.

## Qualifier

`qualifier` (`confirmed` | `likely` | `potential`) is an optional field for assertion strength,
used when a scanner needs to distinguish a confirmed issue from one it merely suspects. It is
required for the API scanner and available to any scanner that needs it; a finding without a
qualifier is a plain static detection.

## Listing rules (`sentinel rules`)

`sentinel rules` aggregates the statically-declared `rules: RuleMeta[]` array from every
registered `ScannerPlugin` and prints them (83 rules across the six built-in scanners today).
Each `RuleMeta` carries `id`, `title`, `severity`, `defaultConfidence`, `category`,
`description`, `recommendation`, and optional `references`. Use `--format json` for a
machine-readable list and `--scanners <ids>` to filter. See [CLI reference](cli.md).

## Authoring a new rule

The full contract is in [Scanner interface](scanner-interface.md); the summary for contributors:

1. Add an entry to the scanner's `rules: RuleMeta[]` with a namespaced id, title, severity,
   default confidence, category, description, and recommendation.
2. Implement detection inside `scan()`, building findings with `createFinding()` from
   `@dl-sentinel/core` so ids are stable fingerprints.
3. Redact before creating — pass any matched value through `redactEvidence(line, [matchedValue])`
   before it goes into a finding. There is no post-hoc redaction step.
4. Use `qualifier` honestly if the scanner distinguishes confirmed/likely/potential assertions.
5. Keep `scan()` deterministic, and check `context.signal.aborted` periodically so long scans stay
   cancellable.
6. Add a **positive fixture** (triggers the rule; a test asserts rule id, severity, file, and
   line) and a **negative fixture** (looks similar, must not trigger), under
   `scanners/<id>/test/fixtures/`.
7. For secret-producing rules, additionally assert the raw fixture secret never appears anywhere
   in `JSON.stringify(findings)`. Keep fixture secrets obviously fake while still matching a
   realistic format.

See [Contributing](contributing.md) for the general pull request process.
