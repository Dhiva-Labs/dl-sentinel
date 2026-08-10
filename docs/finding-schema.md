# Finding Schema

The canonical definition is `Finding` in `packages/core/src/types.ts`. This document
explains field semantics and the invariants reports rely on.

## Example

```json
{
  "id": "9f2c4a1b8d3e6f70",
  "ruleId": "S001",
  "title": "Hardcoded credential detected",
  "description": "A credential-like value was detected.",
  "severity": "critical",
  "confidence": "high",
  "category": "secrets",
  "file": "config/example.env",
  "line": 12,
  "column": 5,
  "evidence": "API_KEY=[REDACTED]",
  "recommendation": "Move the credential to a secure secret store.",
  "references": [],
  "scanner": "secrets"
}
```

## Fields

| Field          | Type                                | Required | Notes |
| -------------- | ----------------------------------- | -------- | ----- |
| id             | string (16 hex)                     | yes      | Stable fingerprint; computed by `createFinding()` |
| ruleId         | string                              | yes      | Namespaced: S/D/C/I/A/SC + number |
| title          | string                              | yes      | Short, human-readable |
| description    | string                              | yes      | What was detected and why it matters |
| severity       | critical/high/medium/low/info       | yes      | See definitions below |
| confidence     | high/medium/low                     | yes      | Detection certainty, not impact |
| qualifier      | confirmed/likely/potential          | no       | Assertion strength (API scanner uses this) |
| category       | enum (see types.ts)                 | yes      | |
| file           | string (repo-relative posix)        | yes      | |
| line / column  | number (1-based)                    | no       | Omit when not meaningful (e.g. whole-file) |
| endLine        | number                              | no       | |
| evidence       | string                              | yes      | ALWAYS redacted; ≤ ~200 chars |
| recommendation | string                              | yes      | Actionable fix |
| references     | string[]                            | yes      | URLs; may be empty |
| scanner        | string                              | yes      | Producing plugin id |
| metadata       | Record<string, string\|number\|boolean> | no  | Scanner-specific extras; never secret material |

## Severity definitions

- **critical** — exploitable now with severe impact (live credential, RCE-equivalent
  pattern, contract fund-drain risk).
- **high** — serious weakness likely exploitable (known-vulnerable dependency in use,
  SQL injection pattern, privileged container).
- **medium** — weakness needing specific conditions (weak crypto, missing TLS
  verification, permissive CORS).
- **low** — hardening gap or hygiene issue (missing resource limits, unpinned image).
- **info** — observation, no direct risk (scanner skipped something, inventory notes).

## Confidence definitions

- **high** — the pattern is unambiguous (structured token format matched, lockfile version
  exactly in a vulnerable range).
- **medium** — the pattern is strong but context could legitimize it.
- **low** — heuristic (entropy-only match, name-based hint). Low-confidence rules should
  be conservative in severity.

## Redaction invariant

`evidence` (and every other field) must never contain a secret value. Producers pass
matched values through `redactEvidence(text, [value])` from `@dl-sentinel/core`, which
replaces every occurrence with `[REDACTED]`, trims, and truncates. Tests for any
secret-producing rule must assert `JSON.stringify(findings)` does not contain the planted
fixture value. Reports (terminal/JSON/Markdown/SARIF), the API server, the dashboard, and
logs render findings as-is and must not add unredacted data of their own.

## Fingerprint (id)

`id = sha256(scanner  ruleId  file  line  column  evidence).hex[0:16]` with
NUL-separated parts (`fingerprint()` in core). Properties: stable across runs on identical
input; distinct for distinct matches on the same line (evidence differs); contains no
secret material because evidence is pre-redacted. The engine dedupes findings by `id`.

## SARIF mapping (reporting)

| severity        | SARIF level |
| --------------- | ----------- |
| critical, high  | error       |
| medium          | warning     |
| low, info       | note        |

Rule metadata maps to `runs[].tool.driver.rules[]`; the finding id is carried in
`partialFingerprints.dlSentinelFindingId`.
