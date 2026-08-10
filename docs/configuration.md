# Configuration

DL Sentinel is configured with a `sentinel.yml` (or `.yaml`) file at the root of the scan target.
Every key is optional: a missing file falls back entirely to built-in defaults, and missing keys
within a present file fall back to the same defaults. An invalid file causes config loading to
throw rather than silently ignoring the problem. Unknown keys produce warnings, not errors.

Defaults come from `defaultConfig()` in `@dl-sentinel/core` (`packages/core/src/types.ts`), which
is implemented today even though the engine that loads and merges it (`loadConfig()` in
`@dl-sentinel/engine`) is still in progress.

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

Settings for `source`, `infra`, `api`, and `smart-contract` are not yet fixed by the contract
docs; each scanner package will declare its own settings shape as it's implemented. See
[Scanners](scanners.md).

## `policy`

| Key | Type | Meaning |
| --- | --- | --- |
| `failOn` | `Severity[]` | Severities that cause a failed policy — and a non-zero CLI exit code — when at least one finding of that severity is present. Default: `[critical, high]`. |

Policy is evaluated by `evaluatePolicy(stats, policy)` in `@dl-sentinel/core`, which returns
`{ pass: boolean, violations: Severity[] }` — `violations` is the subset of `failOn` severities
that actually had findings. See [CLI reference: exit codes](cli.md#exit-codes).

## Precedence

> Status: implementation in progress. `packages/engine` and `apps/cli` are not yet implemented,
> so this order is the intended behavior fixed by the contract rather than something observable
> in this codebase today.

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
