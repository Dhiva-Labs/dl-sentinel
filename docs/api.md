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
| `POST` | `/api/scans` | Start a scan. Body: `{ "path": "/abs/dir", "scanners": ["secrets", ...]? }`. `path` must resolve within `SENTINEL_SCAN_ROOT`; `scanners` is an optional subset of registered scanner ids. |
| `GET` | `/api/scans` | List scans. |
| `GET` | `/api/scans/:id` | Get one scan's detail. |
| `GET` | `/api/scans/:id/findings` | Get the findings for one scan. |
| `GET` | `/api/findings` | Get findings across scans; filterable by severity and scanner. |
| `GET` | `/api/rules` | List rules from registered scanners — the same data `sentinel rules` prints. See [Rules](rules.md#listing-rules-sentinel-rules). |
| `GET` | `/api/reports/:id` | Get a rendered report for a scan. `?format=json\|markdown\|sarif` selects the format. |
| `GET` | `/health` | Health check. |

## Response shapes

- `POST /api/scans` returns `201` with `{ id, status, stats }`, where `stats` is the
  `SeverityStats` object (`critical`, `high`, `medium`, `low`, `info`).
- `GET /api/scans` returns an array of scan summaries: `{ id, project, startedAt, stats,
  findingCount }`.
- `GET /api/scans/:id` returns the full `Report` (see `packages/core/src/types.ts`); `404` if
  unknown.
- `GET /api/scans/:id/findings` and `GET /api/findings` return arrays of `Finding` objects (see
  [Finding schema](finding-schema.md)); both accept `?severity=` and `?scanner=` filters.
- `GET /api/rules` returns an array of rule objects (`RuleMeta` fields plus the owning
  `scanner` id) — the same data `sentinel rules` prints.
- `GET /api/reports/:id?format=json|markdown|sarif` renders a stored `Report` through the same
  `renderReport(report, format)` the CLI uses; default `json`; `404` if unknown.

## Errors

Structured JSON, never a bare string or an HTTP status alone:

```json
{ "error": { "code": "...", "message": "..." } }
```

Current `code` values: `validation_error` (400), `unauthorized` (401), `not_found` (404),
`method_not_allowed` (405), `payload_too_large` (413), `rate_limited` (429), and
`internal_error` (500). Server errors never include a stack trace in the response body.

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
