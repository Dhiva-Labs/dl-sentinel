# DL Sentinel

DL Sentinel is a developer-focused security scanning platform by DhivaLabs. It scans a
repository for exposed secrets, vulnerable dependencies, insecure source code patterns,
container and infrastructure misconfiguration, API definition security issues, and smart-contract
risk patterns, then produces structured findings and reports.

It is built for teams that want static security scanning they can run locally or self-host,
without sending source code to a third-party service — CI/CD usage is a first-class follow-up on
top of the same local scan.

## Scanners

- **Secrets** — detects hardcoded credentials, tokens, and high-entropy strings in tracked
  source. Values are redacted before they enter a finding, report, or log.
- **Dependencies** — flags known-vulnerable dependencies across npm, pip, Go, and Cargo via a
  pluggable data source (none, a local advisory file, or OSV). Never fabricates advisory data.
- **Source code** — flags insecure coding patterns across JS/TS, Python, Go, Ruby, PHP, Java.
- **Infrastructure** — checks Dockerfiles, Compose files, Kubernetes manifests, and basic
  Terraform for misconfiguration.
- **API** — analyzes OpenAPI/Swagger and Postman definitions for security issues.
- **Smart contract** — analyzes Solidity/EVM source with a contract-level model (same-file
  inheritance, modifier bodies, call graph) rather than line heuristics alone.

88 rules in total, 76 of them mapped to CWE and OWASP Top 10 (2021) — see
[docs/scanners.md](docs/scanners.md) and [docs/rules.md](docs/rules.md).

## Beyond scanning

- **Reports** — terminal, JSON, Markdown, or SARIF 2.1.0.
- **Baselines and suppressions** — adopt the tool on an existing codebase and fail only on
  *newly introduced* findings; suppress reviewed findings from `sentinel.yml`, with expiry
  dates so accepted risk resurfaces instead of hiding forever.
- **CI and pull requests** — CI-friendly exit codes, plus a GitHub Action
  ([apps/action](apps/action/README.md)) that reports only what a PR introduced, posts a sticky
  comment, and uploads SARIF.
- **Self-hosted server and dashboard** — a single Node process serving an HTTP API and a
  dependency-free web dashboard: asynchronous scan queue, scheduled scans, history and risk
  trends, role-based access control, and optional webhook/Slack notifications. See
  [docs/deployment.md](docs/deployment.md).
- **Infrastructure graph** — `sentinel graph` renders the deployment surface (services, images,
  volumes, ports, privileged and host-mount edges) as JSON or Mermaid.
- **Extensible** — third-party scanners load as plugins ([docs/plugins.md](docs/plugins.md)).

## Runs standalone

Scanning is fully local and offline: no database, no telemetry, no account, and no network
access unless you explicitly opt in (the OSV dependency data source, notification webhooks, and
the Action's PR comment). Scanned code is never executed, and reports never contain secret
values.

## Quick start

Prerequisites: Node.js 20 or later, and npm.

```bash
git clone https://github.com/Dhiva-Labs/dl-sentinel.git
cd dl-sentinel
npm install
npm run build
npm test
```

Run the CLI (see [docs/cli.md](docs/cli.md)) via `node apps/cli/dist/main.js <command>` after
building, or as `sentinel` once installed:

```bash
sentinel scan .                       # scan a directory with defaults
sentinel scan . --format json|sarif|markdown|terminal
sentinel scan . --fail-on critical,high
sentinel rules                        # list all rules from registered scanners
sentinel version
```

## Configuration

Scans are configured with a `sentinel.yml` at the root of the target:

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

Every key is optional and falls back to built-in defaults. See
[docs/configuration.md](docs/configuration.md) for the full reference.

## Monorepo layout

| Path | Package | Purpose |
| --- | --- | --- |
| `apps/action` | `@dl-sentinel/action` | GitHub Action for pull-request scanning |
| `apps/api` | `@dl-sentinel/api-server` | Self-hosted HTTP API |
| `apps/cli` | `@dl-sentinel/cli` | `sentinel` command-line tool |
| `apps/web` | `@dl-sentinel/web` | Dashboard static assets, served by the API |
| `packages/core` | `@dl-sentinel/core` | Shared types, finding model, utilities |
| `packages/engine` | `@dl-sentinel/engine` | Orchestration: discovery, config, execution |
| `packages/preset` | `@dl-sentinel/preset` | Default engine with every built-in scanner registered |
| `packages/reporting` | `@dl-sentinel/reporting` | Terminal / JSON / Markdown / SARIF renderers |
| `scanners/secrets` | `@dl-sentinel/scanner-secrets` | Secrets scanner |
| `scanners/dependencies` | `@dl-sentinel/scanner-dependencies` | Dependency scanner |
| `scanners/source` | `@dl-sentinel/scanner-source` | Source code scanner |
| `scanners/infra` | `@dl-sentinel/scanner-infra` | Docker and infrastructure scanner |
| `scanners/api` | `@dl-sentinel/scanner-api` | API definition scanner |
| `scanners/smart-contract` | `@dl-sentinel/scanner-smart-contract` | Smart contract scanner |
| `tests/` | — | Cross-package fixtures, integration and e2e tests |
| `docs/` | — | Documentation |

See [docs/architecture.md](docs/architecture.md) for the full design and data flow.

## Documentation

- [Getting started](docs/getting-started.md)
- [Deployment](docs/deployment.md)
- [Scanners](docs/scanners.md)
- [Rules](docs/rules.md)
- [Configuration](docs/configuration.md)
- [CLI reference](docs/cli.md)
- [API reference](docs/api.md)
- [Plugins](docs/plugins.md)
- [Contributing](docs/contributing.md)
- [Security](docs/security.md)
- [Architecture](docs/architecture.md)
- [Scanner interface](docs/scanner-interface.md)
- [Finding schema](docs/finding-schema.md)
- [Development guide](docs/development.md)

## License

Licensed under the MIT License. See [LICENSE](LICENSE).

## Project status

Version 0.1.0. Everything described above is implemented and covered by the test suite: the
scan engine and six scanners, reporting, baselines and suppressions, the `sentinel` CLI, the
GitHub Action, the self-hosted API server (async scan queue, schedules, history and trends,
RBAC, notifications), the web dashboard, the infrastructure graph, and plugin loading.

Every scanner is a precision-tuned static analyzer, not a prover: rules are documented to
under-report rather than guess, findings carry honest severity and confidence, and the
per-component limitations are written down throughout [docs/](docs/) rather than glossed over.
