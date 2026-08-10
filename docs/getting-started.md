# Getting started

## Prerequisites

- Node.js 20 or later
- npm (installed with Node.js)

Everything else installs locally into the workspace; there are no other system dependencies.

## Install, build, and test

```bash
git clone https://github.com/Dhiva-Labs/dl-sentinel.git
cd dl-sentinel
npm install
npm run build
npm test
```

- `npm install` installs dependencies for every package in the workspace.
- `npm run build` runs `tsc -b`, building and type-checking every package via TypeScript project
  references.
- `npm test` runs the full `vitest` suite. Tests import workspace packages by name (for example
  `@dl-sentinel/core`), aliased to source in `vitest.config.ts`, so a prior build is not required
  to run tests.
- Running a built binary for real (rather than through tests) needs the build step first — for
  example `node apps/cli/dist/main.js` once the CLI is implemented.

See [Development guide](development.md) for the full command list and coding conventions.

## Your first scan

> Status: implementation in progress. `apps/cli` currently contains only an interface stub in
> this codebase (`export {}`). The walkthrough below documents the command contract fixed in
> [Architecture](architecture.md) and [CLI reference](cli.md) for when the CLI lands.

Once implemented, scanning a project is a single command:

```bash
sentinel scan .
```

This is expected to:

1. Load `sentinel.yml` (or `.yaml`) from the target directory, falling back to built-in defaults
   if none is present (see [Configuration](configuration.md)).
2. Discover files honoring `include`/`exclude` globs, the `maxFileSizeBytes` cap, binary
   detection, and symlink exclusion.
3. Run every enabled, registered scanner concurrently, isolating failures so one scanner erroring
   does not stop the others.
4. Aggregate and de-duplicate findings, compute severity stats, and print a report.
5. Exit with a status code derived from `policy.failOn` (see [Exit codes](#exit-codes) below).

The terminal report is expected to look like this (from the architecture contract):

```text
DL Sentinel v0.1.0

Scanning: ./project

secrets          2 findings
dependencies     5 findings
source           8 findings
infra            1 finding

Critical: 1
High:     5
Medium:   7
Low:      3
Info:     0

Scan completed.
```

Other invocations from the same contract:

```bash
sentinel scan ./project --config sentinel.yml
sentinel scan . --format json|sarif|markdown|terminal
sentinel scan . --output report.json
sentinel scan . --scanners secrets,dependencies
sentinel scan . --fail-on critical,high
sentinel rules
sentinel version
sentinel report scan.json --format markdown
```

See [CLI reference](cli.md) for the complete command and flag reference.

## Reading a report

Every finding follows the schema in [Finding schema](finding-schema.md). Example:

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

A few things worth noting when reading findings:

- `severity` is impact; `confidence` is detection certainty — a critical finding can still have
  low confidence, and vice versa. See [Rules](rules.md#severity) for definitions of both.
- `evidence` is always redacted before a finding is created. A secret value never appears there,
  in any other field, or anywhere else in a report.
- `id` is a stable fingerprint (see [Finding schema](finding-schema.md#fingerprint-id)); the same
  match on the same input always produces the same id, which is what the engine uses to
  de-duplicate findings across scanners and runs.

The JSON, Markdown, and SARIF renderers for these reports (`@dl-sentinel/reporting`) are already
implemented; only the code that wires a CLI or API run into them is still in progress.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Scan completed and policy passed |
| `1` | Policy violated (findings present at a `--fail-on` / `policy.failOn` severity) |
| `2` | Scan or internal error |
| `64` | Usage error |

See [CLI reference](cli.md#exit-codes) for how CI is expected to consume these.

## Using DL Sentinel in CI

The exit code and `--fail-on` (or `policy.failOn` in `sentinel.yml`) are the mechanism for gating
a build on scan results. An illustrative consumer CI step, once the CLI is implemented:

```yaml
- name: Security scan
  run: npx sentinel scan . --format sarif --output sentinel.sarif --fail-on critical,high
```

A non-zero exit from that step (code `1`) means a finding at `critical` or `high` severity was
present, and the job fails accordingly. This is a sketch of how a *consumer* of DL Sentinel might
wire it into their own pipeline — it is separate from this repository's own CI, which builds and
tests the monorepo itself (see [Contributing](contributing.md)).
