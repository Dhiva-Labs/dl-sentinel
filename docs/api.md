# API reference

> Status: implementation in progress. `apps/api/src/index.ts` currently contains only an
> interface stub (`export {}`) in this codebase. This page documents the endpoint contract fixed
> in [Architecture](architecture.md); request/response shapes beyond what the contract specifies
> are described in terms of the `Finding` and `Report` types in `packages/core/src/types.ts`
> rather than invented.

DL Sentinel ships a self-hosted HTTP API (`apps/api`, package `@dl-sentinel/api-server`) built on
Node's `http` module, without a framework. It serves the dashboard (`@dl-sentinel/web`) at `/`
and exposes the endpoints below under `/api`. Persisted data — scans, findings, the audit log —
lives under the server's local data directory, `.dl-sentinel/`. See
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

Beyond the `POST /api/scans` request body shown above, the contract does not fix full response
bodies field-by-field, but the data itself is drawn from real, implemented types:

- Endpoints returning findings return values shaped like `Finding` in
  [Finding schema](finding-schema.md) (see the worked example there).
- `GET /api/reports/:id` renders a `Report` (see `packages/core/src/types.ts`) through the same
  `renderReport(report, format)` used by the CLI — implemented today in `@dl-sentinel/reporting`,
  independent of whether the HTTP layer that calls it exists yet.

## Errors

Structured JSON, not a bare string or an HTTP status alone:

```json
{ "error": { "code": "...", "message": "..." } }
```

The envelope shape (`error.code`, `error.message`) is fixed by the contract; the specific set of
`code` values is not, and isn't guessed at here.

## Rate limiting

The server applies in-memory rate limiting to protect a self-hosted deployment from abuse.
Specific thresholds are an implementation detail, not fixed by the contract.

## Audit log

Requests are recorded to a JSONL audit log as part of the server's persisted state under
`.dl-sentinel/`.

## What the API server never does

Consistent with the project's read-only guarantee, the API server does not execute scanned code
under any circumstance — starting a scan only ever reads files under the requested path. See
[Security](security.md).
