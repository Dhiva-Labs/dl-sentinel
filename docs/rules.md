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

## Compliance mapping

`RuleMeta.compliance` is an optional field mapping a rule to established compliance
frameworks:

```ts
compliance?: {
  cwe?: string[];    // e.g. ['CWE-798']
  owasp?: string[];  // OWASP Top 10 (2021) ids, e.g. ['A07:2021']
}
```

**The binding rule is that only canonical, well-established mappings are recorded; an
uncertain mapping is omitted, never guessed** (see [Architecture](architecture.md#rule-id-namespaces)).
A wrong compliance mapping actively misleads whoever is using it for an audit or a control
matrix, which is worse than a rule simply not carrying one yet. Concretely:

- `cwe` entries are added when the rule's own `references` already cite a
  cwe.mitre.org definition (the strongest signal — it means whoever wrote the detection
  logic already vetted the mapping), or when the weakness the rule detects has a single,
  textbook-standard CWE (hardcoded credentials → `CWE-798`, SQL injection → `CWE-89`, OS
  command injection → `CWE-78`, path traversal → `CWE-22`, insecure deserialization →
  `CWE-502`, and so on).
- `owasp` entries are added only when the rule's assigned CWE(s) are an official member of
  that OWASP Top 10 (2021) category, per the CWE↔Top-10 mapping MITRE and OWASP jointly
  publish (each `A0x:2021` category page on cwe.mitre.org lists its member CWE ids). This
  keeps the field mechanically checkable rather than a vibes-based guess — see
  `test/compliance.test.ts` in each scanner package, which asserts this consistency.
- For the smart-contract scanner, `owasp` is deliberately never set: OWASP Top 10 (2021) is
  scoped to web application risks, and applying it to Solidity/EVM findings would be
  misleading even when the underlying CWE happens to have a Top-10 category (there is a
  separate OWASP Smart Contract Top 10 for that domain, which this field does not model).
  Smart-contract rules that already cite an SWC Registry entry in `references` keep that as
  their primary taxonomy; `compliance.cwe` is added on top only when the SWC-documented CWE
  relationship (or a more specific, well-corroborated one) is a clean fit for the rule's own
  description.
- When a rule's weakness doesn't map cleanly to any single canonical id, the field — or the
  `cwe`/`owasp` sub-key — is omitted entirely rather than filled with a best guess.

The mapping is rule-level metadata: it describes what *kind* of weakness a rule watches for,
not any particular finding. It is surfaced, verbatim, everywhere rules are listed:
`sentinel rules` (compact `CWE-89 · A03:2021` suffix in the terminal table; the full object
under `--format json`), `GET /api/rules` (the API serves `RuleMeta` as-is), and the
dashboard's Rules view (a chip per id). Findings themselves are unchanged.

The table below is generated from the shipped rule catalog (`sentinel rules --format json`)
and lists every rule that currently carries a mapping. A rule id absent from this table has
no `compliance` field — that is a deliberate omission, not an oversight.

| Rule | Scanner | CWE | OWASP Top 10 (2021) |
| --- | --- | --- | --- |
| `S001` | secrets | CWE-798 | A07:2021 |
| `S002` | secrets | CWE-798 | A07:2021 |
| `S003` | secrets | CWE-798 | A07:2021 |
| `S004` | secrets | CWE-798 | A07:2021 |
| `S005` | secrets | CWE-798 | A07:2021 |
| `S006` | secrets | CWE-798 | A07:2021 |
| `S007` | secrets | CWE-798 | A07:2021 |
| `S008` | secrets | CWE-312 | A04:2021 |
| `S009` | secrets | CWE-798 | A07:2021 |
| `S010` | secrets | CWE-798 | A07:2021 |
| `S011` | secrets | CWE-798 | A07:2021 |
| `S012` | secrets | CWE-798 | A07:2021 |
| `S013` | secrets | CWE-798 | A07:2021 |
| `S014` | secrets | CWE-798 | A07:2021 |
| `S015` | secrets | CWE-798 | A07:2021 |
| `S016` | secrets | CWE-798 | A07:2021 |
| `S017` | secrets | CWE-321, CWE-312 | A02:2021 |
| `S018` | secrets | CWE-798, CWE-312 | A07:2021 |
| `S019` | secrets | CWE-522, CWE-312 | A04:2021 |
| `S020` | secrets | CWE-312 | A04:2021 |
| `S021` | secrets | CWE-798, CWE-312 | A07:2021 |
| `S022` | secrets | CWE-798, CWE-312 | A07:2021 |
| `D001` | dependencies | CWE-1395 | A06:2021 |
| `C001` | source | CWE-78 | A03:2021 |
| `C002` | source | CWE-95 | A03:2021 |
| `C003` | source | CWE-89 | A03:2021 |
| `C004` | source | CWE-502 | A08:2021 |
| `C005` | source | CWE-22 | A01:2021 |
| `C006` | source | CWE-916 | A02:2021 |
| `C007` | source | CWE-330 | A02:2021 |
| `C008` | source | CWE-295 | A07:2021 |
| `C009` | source | CWE-942 | A05:2021 |
| `C010` | source | CWE-732 | — |
| `I001` | infra | CWE-250 | — |
| `I002` | infra | CWE-494 | A08:2021 |
| `I004` | infra | CWE-798 | A07:2021 |
| `I005` | infra | CWE-494 | A08:2021 |
| `I010` | infra | CWE-250 | — |
| `I011` | infra | CWE-653 | A04:2021 |
| `I012` | infra | CWE-668 | A01:2021 |
| `I013` | infra | CWE-250 | — |
| `I014` | infra | CWE-798 | A07:2021 |
| `I015` | infra | CWE-400 | — |
| `I016` | infra | CWE-1327 | — |
| `I020` | infra | CWE-250 | — |
| `I021` | infra | CWE-653 | A04:2021 |
| `I022` | infra | CWE-668 | A01:2021 |
| `I023` | infra | CWE-250 | — |
| `I024` | infra | CWE-250 | — |
| `I025` | infra | CWE-250 | — |
| `I026` | infra | CWE-400 | — |
| `I028` | infra | CWE-798 | A07:2021 |
| `I030` | infra | CWE-284 | A01:2021 |
| `I031` | infra | CWE-668 | A01:2021 |
| `I032` | infra | CWE-798 | A07:2021 |
| `I033` | infra | CWE-311 | A04:2021 |
| `A001` | api | CWE-306 | A07:2021 |
| `A002` | api | CWE-598 | A04:2021 |
| `A003` | api | CWE-319 | A02:2021 |
| `A004` | api | CWE-522 | A04:2021 |
| `A005` | api | CWE-306 | A07:2021 |
| `A006` | api | CWE-200 | A01:2021 |
| `A007` | api | CWE-799 | A04:2021 |
| `A008` | api | CWE-287 | A07:2021 |
| `A009` | api | CWE-20 | A03:2021 |
| `A010` | api | CWE-798 | A07:2021 |
| `SC001` | smart-contract | CWE-841 | — |
| `SC002` | smart-contract | CWE-346 | — |
| `SC003` | smart-contract | CWE-252 | — |
| `SC004` | smart-contract | CWE-829 | — |
| `SC005` | smart-contract | CWE-862 | — |
| `SC006` | smart-contract | CWE-862 | — |
| `SC007` | smart-contract | CWE-862 | — |
| `SC008` | smart-contract | CWE-190 | — |
| `SC010` | smart-contract | CWE-330 | — |
| `SC011` | smart-contract | CWE-477 | — |
| `SC013` | smart-contract | CWE-841 | — |
| `SC014` | smart-contract | CWE-862 | — |
| `SC015` | smart-contract | CWE-252 | — |

79 of the 88 built-in rules currently carry a mapping. The 9 deliberately unmapped rules —
`D002`, `D003`, `I003`, `I006`, `I027`, `SC009`, `SC012`, `SC016`, `SC017` — are
informational or hygiene checks with no single well-established CWE/OWASP id (a dependency
scan being skipped or a manifest missing a lockfile, an unpinned base/container image, an
EXPOSE-only administrative port, a floating Solidity pragma, a privileged setter missing an
event, a privileged address setter missing a zero-address check, a `delegatecall` repeated
inside a loop); each one's rule declaration carries no `compliance` field rather than a
forced guess.

The three new smart-contract mappings reuse mappings already vetted elsewhere in the
catalog rather than introducing new ones: `SC013` is `SC001`'s weakness one call hop
further out (SWC-107 → CWE-841), `SC014` is the same "sensitive function with no
authorization check" shape as `SC005`/`SC006`/`SC007` (CWE-862), and `SC015` is the same
unchecked-return weakness as `SC003` (SWC-104 → CWE-252).

## Listing rules (`sentinel rules`)

`sentinel rules` aggregates the statically-declared `rules: RuleMeta[]` array from every
registered `ScannerPlugin` and prints them (88 rules across the six built-in scanners today).
Each `RuleMeta` carries `id`, `title`, `severity`, `defaultConfidence`, `category`,
`description`, `recommendation`, optional `references`, and optional `compliance` (see
[Compliance mapping](#compliance-mapping) above). Use `--format json` for a machine-readable
list and `--scanners <ids>` to filter. See [CLI reference](cli.md).

## Authoring a new rule

The full contract is in [Scanner interface](scanner-interface.md); the summary for contributors:

1. Add an entry to the scanner's `rules: RuleMeta[]` with a namespaced id, title, severity,
   default confidence, category, description, and recommendation. Add `compliance` only if a
   canonical CWE/OWASP mapping is genuinely defensible (see
   [Compliance mapping](#compliance-mapping)); otherwise leave it unset.
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
