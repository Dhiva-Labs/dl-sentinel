# API reference

DL Sentinel ships a self-hosted HTTP API (`apps/api`, package `@dl-sentinel/api-server`) built on
Node's `http` module, without a framework. Build the workspace and start it with
`node apps/api/dist/main.js` (or the `sentinel-api` bin). It listens on `PORT` (default `8752`),
serves the dashboard (`@dl-sentinel/web`) at `/`, and exposes the endpoints below under `/api`.
Persisted data — scans, findings, the audit log — lives under the server's local data directory
(`SENTINEL_DATA_DIR`, default `.dl-sentinel/`). See
[Security](security.md#what-the-api-server-stores-and-where).

## Authentication

Bearer-token auth, via the `SENTINEL_API_TOKEN` environment variable. If it is unset, the server
generates a token and prints it at startup. Requests authenticate with:

```text
Authorization: Bearer <token>
```

Token comparison is constant-time, to avoid leaking information through response-time
differences.

## Scan path restriction

`SENTINEL_API_TOKEN` gates *who* can call the API; `SENTINEL_SCAN_ROOT` gates *what* it can scan.
It configures an allowlisted base directory — a `path` submitted to `POST /api/scans` must
resolve inside it, or the request is rejected. This prevents an authenticated caller from pointing
the server at arbitrary filesystem locations.

## Endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/scans` | Enqueue a scan (runs asynchronously; see [Asynchronous scans](#asynchronous-scans)). Body: `{ "path": "/abs/dir", "scanners": ["secrets", ...]? }`. `path` must resolve within `SENTINEL_SCAN_ROOT`; `scanners` is an optional subset of registered scanner ids. Returns `202`. |
| `GET` | `/api/scans` | List scan records with their status. |
| `GET` | `/api/scans/:id` | Get one scan record (includes its `report` once completed, or an `error` when failed). |
| `GET` | `/api/scans/:id/findings` | Get the findings for one completed scan. `409` while it is still queued/running. |
| `GET` | `/api/findings` | Get findings across completed scans; filterable by severity and scanner. |
| `GET` | `/api/rules` | List rules from registered scanners — the same data `sentinel rules` prints. See [Rules](rules.md#listing-rules-sentinel-rules). |
| `GET` | `/api/reports/:id` | Get a rendered report for a completed scan. `?format=json\|markdown\|sarif` selects the format. `409` while it is still queued/running. |
| `POST` | `/api/schedules` | Create a scheduled scan. Body: `{ "path": "/abs/dir", "intervalMs": 3600000, "scanners": ["secrets", ...]? }`. Same validation as `POST /api/scans`, plus `intervalMs` must be a number `>= 60000` (60s). Returns `201` with the schedule record. See [Scheduled scans](#scheduled-scans). |
| `GET` | `/api/schedules` | List schedule records (newest first). |
| `GET` | `/api/schedules/:id` | Get one schedule record. `404` if unknown. |
| `PATCH` | `/api/schedules/:id` | Update a schedule. Body: `{ "enabled"?: boolean, "intervalMs"?: number }`. Returns `200` with the updated record; `404` if unknown. Changing `intervalMs` recomputes `nextRunAt` from now. |
| `DELETE` | `/api/schedules/:id` | Delete a schedule. Returns `204`; `404` if unknown. |
| `GET` | `/api/history` | Chronological (oldest-first) list of completed scans, reduced to their outcome. Query: `?target=<path>` filters to one scanned path; `?limit=<n>` keeps the most recent `n` (still oldest-first). See [Response shapes](#response-shapes). |
| `GET` | `/api/trends` | Per-scan severity time series for charting, oldest-first. Query: `?target=<path>` filters to one scanned path. Derived from stored records — scans are never recomputed. |
| `GET` | `/health` | Health check. |

## Response shapes

- `POST /api/scans` returns `202` with `{ id, status: "queued" }` — the scan is enqueued, not
  yet run. Body validation (JSON shape, `path` within `SENTINEL_SCAN_ROOT`, known `scanners`)
  still happens synchronously, so an invalid request is rejected with `400` before anything is
  queued.
- `GET /api/scans` returns an array of scan summaries: `{ id, status, path, createdAt }`, plus
  `startedAt`/`finishedAt` once they exist and, for completed scans, the report-derived
  `project`, `durationMs`, `scannersRun`, `stats` (the `SeverityStats` object) and
  `findingCount`.
- `GET /api/scans/:id` returns the full scan record: `{ id, status, path, scanners?, createdAt,
  startedAt?, finishedAt?, report?, error? }`. `report` is present iff `status === "completed"`;
  `error` (a client-safe message) is present iff `status === "failed"`. `404` if unknown.
- `GET /api/scans/:id/findings` and `GET /api/findings` return arrays of `Finding` objects (see
  [Finding schema](finding-schema.md)); both accept `?severity=` and `?scanner=` filters.
  `/api/findings` aggregates across completed scans only. A per-scan request for a scan that has
  not completed returns `409` (see [Asynchronous scans](#asynchronous-scans)).
- `GET /api/rules` returns an array of rule objects (`RuleMeta` fields plus the owning
  `scanner` id) — the same data `sentinel rules` prints.
- `GET /api/reports/:id?format=json|markdown|sarif` renders a completed scan's `Report` through
  the same `renderReport(report, format)` the CLI uses; default `json`; `404` if unknown, `409`
  if not yet completed.
- `POST /api/schedules` returns `201` with the full schedule record: `{ id, path, scanners?,
  intervalMs, enabled, createdAt, lastRunAt?, lastScanId?, nextRunAt }`. `path` is the canonical
  (realpath'd) target; `enabled` defaults to `true`; `nextRunAt` is `createdAt + intervalMs`.
  `GET /api/schedules` returns an array of these (newest first); `GET /api/schedules/:id` returns
  one; `PATCH` returns the updated record; `DELETE` returns `204` with an empty body.
- `GET /api/history` returns an array of `{ id, path, project, finishedAt, stats, findingCount }`,
  oldest-first, over completed scans only. `?target=` filters by exact scanned path; `?limit=<n>`
  (a positive integer, else `400`) keeps the most recent `n` entries in that same order.
- `GET /api/trends` returns an array of `{ finishedAt, critical, high, medium, low, info, total }`,
  oldest-first, over completed scans only (optionally filtered by `?target=`). `total` is the sum
  of the severity buckets. Both endpoints derive purely from stored records; they never re-run a
  scan.

## Asynchronous scans

`POST /api/scans` enqueues a job and returns immediately; the scan runs in the background so the
request is never held open for the duration of a scan. The lifecycle is:

```text
queued ──► running ──► completed   (report available)
                   └──► failed      (error message available)
```

A bounded in-process worker pool executes jobs. Its size comes from
`SENTINEL_SCAN_CONCURRENCY` (default `2`; a non-positive or unparseable value falls back to the
default). No more than that many scans run at once; additional jobs wait as `queued`.

Poll `GET /api/scans/:id` to follow a job. Endpoints that need a finished report
(`GET /api/scans/:id/findings`, `GET /api/reports/:id`) return `409` with
`{ "error": { "code": "scan_not_ready", "message": "..." } }` until the scan is `completed`; a
`failed` scan likewise has no report and returns `409` there (its `error` is on the record from
`GET /api/scans/:id`). `GET /api/findings` is not tied to a single scan — it aggregates the
findings of completed scans only, so it returns `200` (possibly an empty array) rather than
`409`.

Records and their status are persisted under `SENTINEL_DATA_DIR`, so they survive a restart.
On startup the server reconciles persisted state after a possible unclean shutdown: a record
left `running` is marked `failed` with the message `interrupted by restart`, and a record still
`queued` is re-enqueued so the worker resumes it. Completed and failed records are never re-run.

## Scheduled scans

A schedule enqueues a scan for a fixed `path` every `intervalMs` while `enabled`. Create one with
`POST /api/schedules`; it validates exactly like `POST /api/scans` (path within
`SENTINEL_SCAN_ROOT`, known scanner ids) and additionally requires `intervalMs` to be a number at
or above `60000` (60 seconds) — a smaller or non-numeric value is a `400`.

A background scheduler wakes on a fixed interval (`SENTINEL_SCHEDULER_INTERVAL_MS`, default
`15000`) and, for each enabled schedule whose `nextRunAt` has passed, enqueues a scan through the
same worker pool as ad-hoc scans (it never runs a scan itself) and advances `nextRunAt` a full
interval past now. The scheduled run appears in `GET /api/scans` like any other; the schedule's
`lastRunAt`/`lastScanId` point at the most recent one.

Schedules are persisted under `SENTINEL_DATA_DIR` and resume across a restart. On reload
`nextRunAt` is recomputed: a schedule that came due during downtime is set to run once promptly on
the next tick (not once per missed interval). A scheduling error never crashes the server — it is
logged and the tick moves on.

## Errors

Structured JSON, never a bare string or an HTTP status alone:

```json
{ "error": { "code": "...", "message": "..." } }
```

Current `code` values: `validation_error` (400), `invalid_json` (400), `unauthorized` (401),
`not_found` (404), `method_not_allowed` (405), `scan_not_ready` (409), `payload_too_large`
(413), `rate_limited` (429), and `internal_error` (500). Server errors never include a stack
trace in the response body, and a failed scan's `error` message is sanitized — engine
validation messages are surfaced as-is, but any other failure collapses to a generic message so
internal detail never leaks.

## Rate limiting

In-memory, fixed-window rate limiting protects a self-hosted deployment from abuse. Defaults are
60 requests per 60 seconds, configurable via `SENTINEL_RATE_LIMIT_MAX` and
`SENTINEL_RATE_LIMIT_WINDOW_MS`; exceeding the window returns `429` with a `Retry-After` header.
Request bodies are capped at `SENTINEL_MAX_BODY_BYTES` (default 1 MiB) → `413`.

## Audit log

Requests are recorded to a JSONL audit log as part of the server's persisted state under
`.dl-sentinel/`.

## What the API server never does

Consistent with the project's read-only guarantee, the API server does not execute scanned code
under any circumstance — starting a scan only ever reads files under the requested path. See
[Security](security.md).
