# CLI reference

> Status: implementation in progress. `apps/cli/src/index.ts` currently contains only an
> interface stub (`export {}`) in this codebase. This page documents the command contract fixed
> in [Architecture](architecture.md); it is not a description of a working binary yet.

Binary name: `sentinel` (package `@dl-sentinel/cli`, `apps/cli`).

## Commands

### `sentinel scan <target>`

Scans a directory with the registered scanners and prints a report.

| Flag | Value | Meaning |
| --- | --- | --- |
| `--config <path>` | file path | Use an explicit `sentinel.yml` instead of discovering one in the target. |
| `--format <format>` | `terminal` \| `json` \| `sarif` \| `markdown` | Output format. Defaults to `terminal`. |
| `--output <path>` | file path | Write the report to a file instead of stdout. |
| `--scanners <ids>` | comma-separated scanner ids | Run only this subset of registered scanners. |
| `--fail-on <severities>` | comma-separated severities | Override `policy.failOn` for this run. |

Examples:

```bash
sentinel scan .                       # scan a directory with defaults
sentinel scan ./project --config sentinel.yml
sentinel scan . --format json|sarif|markdown|terminal
sentinel scan . --output report.json  # write to file instead of stdout
sentinel scan . --scanners secrets,dependencies
sentinel scan . --fail-on critical,high
```

### `sentinel rules`

Lists every rule from every registered scanner. See [Rules](rules.md#listing-rules-sentinel-rules).

```bash
sentinel rules
```

### `sentinel version`

Prints the tool name and version (`DL Sentinel` / `0.1.0` today, from `TOOL_NAME` /
`TOOL_VERSION` in `@dl-sentinel/core`).

```bash
sentinel version
```

### `sentinel report <file>`

Re-renders a previously saved JSON report in another format, without re-scanning.

| Flag | Value | Meaning |
| --- | --- | --- |
| `--format <format>` | `terminal` \| `json` \| `sarif` \| `markdown` | Output format. |

```bash
sentinel report scan.json --format markdown
```

## Terminal output

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

This shape is produced by `renderTerminal()` in `@dl-sentinel/reporting`, which is already
implemented and tested — per-scanner finding counts, then a severity summary, then any scanner
errors, then a closing line.

## Output formats

`terminal`, `json`, `markdown`, and `sarif` renderers are implemented today in
`@dl-sentinel/reporting` (`packages/reporting/src`); what's still in progress is the CLI code
that calls them. SARIF output targets SARIF 2.1.0; severity maps to SARIF level as follows (see
[Finding schema](finding-schema.md#sarif-mapping-reporting)):

| Severity | SARIF level |
| --- | --- |
| critical, high | error |
| medium | warning |
| low, info | note |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Scan ok and policy passed |
| `1` | Policy violated (findings at a fail-on severity) |
| `2` | Scan or internal error |
| `64` | Usage error |

CI is expected to use these directly — see [Getting started: using DL Sentinel in
CI](getting-started.md#using-dl-sentinel-in-ci).
