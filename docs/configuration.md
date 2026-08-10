# Configuration

DL Sentinel is configured with a `sentinel.yml` (or `.yaml`) file at the root of the scan target.
Every key is optional: a missing file falls back entirely to built-in defaults, and missing keys
within a present file fall back to the same defaults. An invalid file causes config loading to
throw rather than silently ignoring the problem. Unknown keys produce warnings, not errors.

Defaults come from `defaultConfig()` in `@dl-sentinel/core` (`packages/core/src/types.ts`); the
engine's `loadConfig()` (`@dl-sentinel/engine`) discovers the file, deep-merges it over those
defaults, and warns on unknown keys.

## Full reference

```yaml
include:
  - '**/*'
exclude:
  - '**/node_modules/**'
maxFileSizeBytes: 1048576
scanners:
  secrets:
    enabled: true
    allowlist: []          # exact strings or rule ids to suppress
    ignorePaths: []
  dependencies:
    dataSource: none       # none | file | osv   (osv requires network, off by default)
    advisoryDbPath: null
policy:
  failOn: [critical, high]
suppress:
  - rule: S008             # match by rule id
    path: '**/*.test.env'  # AND by file glob
    reason: fake keys used in tests
    expires: 2027-01-01    # optional; the rule lapses on/after this date
  - id: 9f2c4a1b8d3e6f70   # or pin a single finding by fingerprint
    reason: accepted risk, tracked in TICKET-123
```

## `include` / `exclude`

Both are glob pattern lists evaluated against the repo-relative posix path of each discovered
file, using the same matcher scanners use for `supportedFiles` — see
[Scanner interface: glob semantics](scanner-interface.md#glob-semantics-for-supportedfiles) for
the full pattern rules (`**` for any depth, `*` within a segment, `?` for one non-slash
character, `{a,b}` alternation, a trailing `/` for a whole directory).

Two details worth calling out:

- **Dotfiles are matched normally** — they are not excluded by default. Files like `.env` are
  prime scan targets, so the matcher never special-cases a leading dot.
- **Negation is supported** with a leading `!`, gitignore-style: patterns are applied in order
  and the *last* pattern that matches a given path decides whether it's included, so a later `!`
  can re-include something excluded earlier.

### Default excludes

`exclude` defaults to `DEFAULT_EXCLUDES` in core:

```text
**/node_modules/**
**/.git/**
**/dist/**
**/build/**
**/out/**
**/coverage/**
**/.next/**
**/.venv/**
**/venv/**
**/__pycache__/**
**/target/debug/**
**/target/release/**
**/.dl-sentinel/**
**/*.min.js
**/*.min.css
**/*.map
```

## `maxFileSizeBytes`

Default `1048576` (1 MiB). Files over this size are excluded at file-discovery time; a scanner's
`readFile()` never returns content for a file larger than the configured cap, so there is no way
to accidentally read an oversized file from inside a scanner.

## `scanners`

A section per scanner, keyed by the scanner's `id` (`secrets`, `dependencies`, `source`, `infra`,
`api`, `smart-contract`). Every section supports:

- `enabled` (boolean, default `true`) — a scanner with `enabled: false` is never invoked.

Beyond `enabled`, only two scanners have settings fixed by the contract today:

**`scanners.secrets`**

| Key | Type | Meaning |
| --- | --- | --- |
| `allowlist` | `string[]` | Exact strings or rule ids to suppress. |
| `ignorePaths` | `string[]` | Additional path patterns to skip, beyond the global `exclude` list. |

**`scanners.dependencies`**

| Key | Type | Meaning |
| --- | --- | --- |
| `dataSource` | `'none' \| 'file' \| 'osv'` | Where vulnerability data comes from. `none` (default) means "not checked", reported honestly rather than fabricated. `file` reads a local advisory file. `osv` queries the OSV database over the network and is off by default. |
| `advisoryDbPath` | `string \| null` | Path to the local advisory file when `dataSource: file`. |

The `source`, `infra`, `api`, and `smart-contract` scanners honor the common `enabled` flag and
otherwise take no required settings today. See [Scanners](scanners.md) for their supported files.

## `policy`

| Key | Type | Meaning |
| --- | --- | --- |
| `failOn` | `Severity[]` | Severities that cause a failed policy — and a non-zero CLI exit code — when at least one finding of that severity is present. Default: `[critical, high]`. |

Policy is evaluated by `evaluatePolicy(stats, policy)` in `@dl-sentinel/core`, which returns
`{ pass: boolean, violations: Severity[] }` — `violations` is the subset of `failOn` severities
that actually had findings. See [CLI reference: exit codes](cli.md#exit-codes).

## `suppress`

A list of suppression rules applied to findings after scanning, so a project can drop findings it
has reviewed and accepted. This is the general, finding-model-level form of the per-scanner
allowlists (e.g. `scanners.secrets.allowlist`): every scanner's output passes through it. Suppressed
findings are removed from `report.findings` and from the severity stats, and their number is
recorded in `report.suppressed`.

Each entry is a rule with these optional fields:

| Key | Type | Meaning |
| --- | --- | --- |
| `rule` | `string` | Match findings emitted by this rule id, e.g. `S001`. |
| `scanner` | `string` | Match findings produced by this scanner id, e.g. `secrets`. |
| `path` | `string` | Match findings whose repo-relative file matches this glob (same semantics as `include`/`exclude`). |
| `id` | `string` | Match a single finding by its stable fingerprint id. |
| `reason` | `string` | Audit trail only; not used for matching. |
| `expires` | `string` | ISO-8601 date; on/after this date the rule stops suppressing. |

Matching semantics:

- **Every field a rule specifies must match** (logical AND). A rule with `rule: S008` and
  `path: '**/*.test.env'` suppresses an `S008` finding only when it is also in a `*.test.env` file.
- A finding is suppressed when it matches **any** active rule (logical OR across rules).
- A rule that specifies **no matcher** (`rule`/`scanner`/`path`/`id`) matches nothing, so a blank or
  reason-only entry can never hide everything by accident.
- **Expiry.** When `expires` is set, the rule stops suppressing on or after that date and the
  finding **resurfaces** rather than staying hidden forever — a deliberate nudge to re-review
  accepted risk. An unparseable `expires` value is treated as "never expires".

Malformed input is lenient rather than fatal: if `suppress` is not a list, or an individual entry is
not a mapping or has a non-string field, DL Sentinel warns and ignores that piece and keeps going,
so one typo cannot abort an entire scan. (Every other config error throws.)

Baselines are a related but separate mechanism for reporting only newly introduced findings; they
live in their own file rather than in `sentinel.yml`. See
[CLI reference: baseline semantics](cli.md#sentinel-scan-target) and
[`sentinel baseline`](cli.md#sentinel-baseline-target).

## Precedence

Highest to lowest:

1. Flags passed to the current CLI invocation (`--scanners`, `--fail-on`, `--format`, and so on)
   — these apply only to that run.
2. An explicit `--config <path>` file.
3. `sentinel.yml` (or `.yaml`) discovered in the scan target directory.
4. Built-in defaults (`defaultConfig()`).

This mirrors the engine's `loadConfig(targetDir, configPath?)` contract in
[Architecture](architecture.md) (see the `@dl-sentinel/engine` package contract): an explicit
path is preferred over discovery in the target directory, and discovery is preferred over
defaults.
