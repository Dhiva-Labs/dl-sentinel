# DL Sentinel Architecture

DL Sentinel is a developer-focused security platform that scans repositories, dependencies,
containers, infrastructure configuration, APIs, secrets, and smart contracts, producing
structured findings and audit reports. It is designed for local/self-hosted operation first,
with CI/CD usage as a first-class follow-up.

## Design principles

1. **Read-only by default.** Scanning never executes repository code, never runs package
   scripts, and never modifies the target.
2. **Secrets never leak.** Secret values found during scanning are redacted before they enter
   a finding, report, log line, or terminal. See `docs/finding-schema.md`.
3. **Deterministic scanners.** Same input → same findings. Network-dependent data sources
   (e.g. vulnerability databases) sit behind explicit adapters and are disabled in tests.
4. **Failure isolation.** One failing scanner must not terminate the scan; its error is
   recorded in the report and the rest of the scan completes.
5. **Minimal supply chain.** Runtime dependencies are kept near zero. Currently the only
   approved runtime dependency is `yaml` (config parsing, infrastructure scanning). New
   dependencies require lead approval and a written rationale.
6. **Extensible core.** Scanners are plugins behind a stable interface; external tools
   (Semgrep, Trivy, OSV, Slither) can be integrated later as optional adapters, never as
   hard requirements.

## Monorepo layout

```text
dl-sentinel/
├── apps/
│   ├── api/        @dl-sentinel/api-server  — self-hosted HTTP API
│   ├── cli/        @dl-sentinel/cli         — `sentinel` command line tool
│   └── web/        @dl-sentinel/web         — dashboard static assets, served by the API
├── packages/
│   ├── core/       @dl-sentinel/core        — shared types, finding model, utilities
│   ├── engine/     @dl-sentinel/engine      — orchestration: discovery, config, execution
│   └── reporting/  @dl-sentinel/reporting   — terminal / JSON / Markdown / SARIF renderers
├── scanners/
│   ├── secrets/          @dl-sentinel/scanner-secrets
│   ├── dependencies/     @dl-sentinel/scanner-dependencies
│   ├── source/           @dl-sentinel/scanner-source
│   ├── infra/            @dl-sentinel/scanner-infra   (Dockerfile, compose, k8s, basic Terraform)
│   ├── api/              @dl-sentinel/scanner-api     (OpenAPI/Swagger/Postman analysis)
│   └── smart-contract/   @dl-sentinel/scanner-smart-contract (Solidity/EVM patterns)
├── tests/          cross-package fixtures, integration and e2e tests
└── docs/
```

Deviations from the original plan document, chosen deliberately:

- `packages/findings`, `packages/rules`, `packages/config`, `packages/shared` are folded into
  `core` (data model) and `engine` (behavior). Fewer packages, same boundaries.
- The Docker scanner and infrastructure scanner are one package (`scanners/infra`) — they
  share parsing and fixtures.
- The dashboard is a dependency-free static app served by the API server; `@dl-sentinel/web`
  exports `getWebRoot()` so the server can locate its assets.

## Data flow

```text
target directory
      |
      v
engine: load config (sentinel.yml) ── defaults from @dl-sentinel/core
      |
      v
engine: file discovery  (include/exclude globs, binary sniff, size cap, no symlink follow)
      |
      v
engine: for each registered scanner (concurrently, isolated):
      |     files filtered to scanner.supportedFiles → scanner.scan(context) → Finding[]
      |     a scanner throw becomes a ScannerError, scan continues
      v
engine: aggregate → dedupe by finding id → sort → Report (stats, findings, errors)
      |
      v
reporting: terminal | json | markdown | sarif
      |
      v
consumers: CLI (exit code from policy), API server (persist + serve), dashboard (render)
```

## Package contracts

### @dl-sentinel/core (stable — changes require lead sign-off)

Owns the shared data model: `Finding`, `RuleMeta`, `ScannerPlugin`, `ScanContext`,
`Report`, `SentinelConfig`, `ScanEvent`, severity/confidence types, plus utilities:
redaction (`redactEvidence`, `REDACTED`), entropy, glob matching (`createMatcher`),
fingerprinting (`createFinding`, `dedupeFindings`), stats (`computeStats`,
`evaluatePolicy`, `sortFindings`).

### @dl-sentinel/engine

Public API (implemented on `feature/sentinel-core`):

```ts
import type {
  Report, ScanEvent, ScannerPlugin, SentinelConfig, ScanLogger,
} from '@dl-sentinel/core';

export interface ScanOptions {
  target: string;                 // directory to scan
  config?: SentinelConfig;        // already-loaded config (wins over configPath)
  configPath?: string;            // explicit sentinel.yml path
  scanners?: string[];            // subset of registered scanner ids to run
  signal?: AbortSignal;           // cooperative cancellation
  onEvent?: (event: ScanEvent) => void;
  logger?: ScanLogger;
}

export interface ScanEngine {
  register(plugin: ScannerPlugin): void;
  /** Registered plugins, in registration order. */
  plugins(): readonly ScannerPlugin[];
  scan(options: ScanOptions): Promise<Report>;
}

export function createEngine(): ScanEngine;

/** Load sentinel.yml (or .yaml); missing file → defaults; invalid file → throws. */
export function loadConfig(targetDir: string, configPath?: string): Promise<SentinelConfig>;
```

Error-name conventions consumers may rely on: engine usage errors (nonexistent/invalid
target, unknown scanner id in `options.scanners`, duplicate registration, missing explicit
`configPath`) are thrown with `error.name === 'UsageError'`; cancellation rejects with
`error.name === 'AbortError'`. The CLI maps UsageError → exit 64, AbortError/other → exit 2.

Engine responsibilities: config loading/merging with defaults, file discovery honoring
include/exclude and `maxFileSizeBytes`, binary detection (NUL-byte sniff of the first 8 KiB),
never following symlinks, per-scanner file filtering via `supportedFiles`, concurrent
execution with error isolation, `scanners[id].enabled === false` handling, event emission,
dedupe via finding ids, applying suppression rules, stats computation, and assembling the
final `Report`.

### Suppressions and baselines (@dl-sentinel/core)

Two finding-model mechanisms let a project manage findings it has already reviewed. Both are
implemented and tested in `@dl-sentinel/core`; the engine, CLI, and reporting consume them.

**Suppressions** — declared in `sentinel.yml` under `suppress` (a `SuppressionRule[]`):

```yaml
suppress:
  - rule: S008 # match by rule id
    path: '**/*.test.env' # AND by file glob
    reason: fake keys used in tests
    expires: 2027-01-01 # optional; the rule lapses after this date
  - id: 9f2c4a1b8d3e6f70 # or pin a single finding by fingerprint
    reason: accepted risk, tracked in TICKET-123
```

A finding is suppressed when it matches any **active** rule; within a rule every specified
field must match (`rule`, `scanner`, `path`, `id`), and a rule with no matcher suppresses
nothing. The engine applies `applySuppressions(findings, config.suppress, new Date())` during
report assembly: `report.findings` contains only the survivors and `report.suppressed` records
how many were dropped. This is the general form of the per-scanner allowlists (e.g. secrets).

**Baselines** — a saved set of known finding ids (fingerprints), produced by `createBaseline`
and consumed by `applyBaseline`. Because ids are stable, a baseline is effectively an id set;
`applyBaseline(findings, baseline)` partitions findings into `newFindings` and `baselined`.
The CLI uses this so a scan can report/fail on only newly introduced findings:

```bash
sentinel baseline .                       # write a baseline (default .sentinel-baseline.json)
sentinel scan . --baseline .sentinel-baseline.json   # report only new findings
sentinel scan . --write-baseline path.json           # scan and (re)write a baseline
```

When a baseline is applied, the policy/exit code is evaluated against the NEW findings only,
and `report.baseline = { newFindings, baselined }` is populated. `parseBaseline` validates an
untrusted baseline file's shape (a security tool must not trust it blindly).

### @dl-sentinel/reporting

`renderReport(report, format)` where format ∈ `terminal | json | markdown | sarif`.
Terminal output follows the format shown in the CLI section below. SARIF output targets
SARIF 2.1.0. Reports must never contain unredacted secrets — they render findings as-is,
and findings are already redacted at creation time.

### CLI (`apps/cli`, binary name `sentinel`)

```bash
sentinel scan .                       # scan a directory with defaults
sentinel scan ./project --config sentinel.yml
sentinel scan . --format json|sarif|markdown|terminal
sentinel scan . --output report.json  # write to file instead of stdout
sentinel scan . --scanners secrets,dependencies
sentinel scan . --fail-on critical,high
sentinel rules                        # list all rules from registered scanners
sentinel version
sentinel report scan.json --format markdown   # re-render a saved JSON report
```

Terminal scan output shape:

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

Exit codes: `0` scan ok and policy passed · `1` policy violated (findings at fail-on
severities) · `2` scan/internal error · `64` usage error. CI uses these directly.

### API server (`apps/api`)

Self-hosted HTTP server (Node `http`, no framework). Endpoints:

```text
POST /api/scans            { "path": "/abs/dir", "scanners": ["secrets", ...]? }
GET  /api/scans
GET  /api/scans/:id
GET  /api/scans/:id/findings
GET  /api/findings         (across scans; filterable by severity/scanner)
GET  /api/rules
GET  /api/reports/:id      (?format=json|markdown|sarif)
GET  /health
```

Requirements: bearer-token auth (`SENTINEL_API_TOKEN`; generated and printed at startup if
unset), constant-time token comparison, request validation, in-memory rate limiting,
scan-path restriction to an allowlisted base directory (`SENTINEL_SCAN_ROOT`), JSONL audit
log, structured error responses `{ "error": { "code", "message" } }`, findings persisted
under the server data directory (`.dl-sentinel/`), and no execution of scanned code.
The server serves the dashboard from `@dl-sentinel/web` `getWebRoot()` at `/`.

**Asynchronous scans.** `POST /api/scans` enqueues a job and returns `202` with
`{ id, status: "queued" }` immediately rather than blocking until the scan finishes. A bounded
in-process worker (concurrency from `SENTINEL_SCAN_CONCURRENCY`, default 2) runs jobs. A scan
record has `status ∈ queued | running | completed | failed`; `GET /api/scans/:id` returns the
record with its `report` once `completed` (and an `error` message when `failed`). `GET
/api/scans` lists records with their status. Endpoints that need a finished report
(`/findings`, `/reports/:id`) return `409 { error: { code: "scan_not_ready" } }` while a scan
is still queued/running. Jobs and their status survive restart via the existing on-disk store;
a job left `running` at shutdown is marked `failed` (interrupted) on reload. This keeps the
server responsive and is the substrate the scheduled-scan feature builds on.

**Scheduled scans and trends.** Schedules (`{ id, path, scanners?, intervalMs, enabled,
nextRunAt, ... }`) are persisted alongside scan records. A background scheduler enqueues a scan
through the same worker pool for each enabled, due schedule and advances `nextRunAt`; it delegates
to the queue rather than running scans itself, resumes across restart (recomputing `nextRunAt` so
an overdue schedule runs once, not N times), and never lets a scheduling error crash the server.
`GET /api/history` and `GET /api/trends` derive read-only history and per-severity time series
from stored completed scans. Endpoints and shapes are in `docs/api.md`.

### Dashboard (`apps/web`)

Static, dependency-free HTML/CSS/JS. Pages: Dashboard (severity overview, recent scans,
top findings, findings-trend sparkline), Scans (status column; trigger a scan and poll it to
completion), Schedules (create/enable/disable/delete), Findings (detail: rule, severity,
confidence, file/line, sanitized evidence, remediation, references), Trends (dependency-free SVG
severity-over-time chart), Rules, Reports, Settings (API token entry, stored in browser
localStorage). Scan detail follows the async lifecycle — it shows queued/running status, polls
until terminal, then loads the report, and handles a `409` from report endpoints gracefully. Talks
only to the API above.

## Configuration (`sentinel.yml`)

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

Unknown keys produce warnings, not errors. Defaults come from `defaultConfig()` in core.

## Rule id namespaces

| Prefix | Scanner        | Example |
| ------ | -------------- | ------- |
| S      | secrets        | S001    |
| D      | dependencies   | D001    |
| C      | source code    | C001    |
| I      | infra/docker   | I001    |
| A      | api            | A001    |
| SC     | smart-contract | SC001   |

## Security posture (binding)

Never: log secrets, execute repository scripts, follow symlinks during discovery, upload
source anywhere, claim a vulnerability is exploitable without verification, claim a target
is secure because no rule fired. Prefer: least privilege, explicit permissions, bounded
memory, deterministic output, audit logs. The dependency scanner must not fabricate
vulnerability data — it reports only what its configured data source returned, and reports
"not checked" when no source is configured.

## Roadmap after MVP

Phase 2: GitHub/GitLab/Bitbucket integration, PR scanning, scheduled scans, baselines,
suppressions, org dashboard. Phase 3: hosted server, teams/RBAC, notifications,
Slack/webhooks, trends, compliance mapping. Phase 4: plugin marketplace, deeper
smart-contract analysis, infra graph, attack-path analysis.
