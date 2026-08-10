# DL Sentinel

DL Sentinel is a developer-focused security scanning platform by DhivaLabs. It scans a
repository for exposed secrets, vulnerable dependencies, insecure source code patterns,
container and infrastructure misconfiguration, API definition security issues, and smart-contract
risk patterns, then produces structured findings and reports.

It is built for teams that want static security scanning they can run locally or self-host,
without sending source code to a third-party service — CI/CD usage is a first-class follow-up on
top of the same local scan.

## Features

- **Secrets** — detects hardcoded credentials, tokens, and high-entropy strings in tracked
  source.
- **Dependencies** — flags known-vulnerable dependencies via a pluggable data source (none, a
  local file, or OSV).
- **Source code** — flags insecure coding patterns in application source.
- **Infrastructure** — checks Dockerfiles, Compose files, Kubernetes manifests, and basic
  Terraform for misconfiguration.
- **API** — analyzes OpenAPI/Swagger and Postman definitions for security issues.
- **Smart contract** — analyzes Solidity/EVM source for risk patterns.

Reports render as terminal output, JSON, Markdown, or SARIF 2.1.0.

All six scanners ship 83 rules in total — see [docs/scanners.md](docs/scanners.md) and
[docs/rules.md](docs/rules.md).

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
| `apps/api` | `@dl-sentinel/api-server` | Self-hosted HTTP API |
| `apps/cli` | `@dl-sentinel/cli` | `sentinel` command-line tool |
| `apps/web` | `@dl-sentinel/web` | Dashboard static assets, served by the API |
| `packages/core` | `@dl-sentinel/core` | Shared types, finding model, utilities |
| `packages/engine` | `@dl-sentinel/engine` | Orchestration: discovery, config, execution |
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
- [Scanners](docs/scanners.md)
- [Rules](docs/rules.md)
- [Configuration](docs/configuration.md)
- [CLI reference](docs/cli.md)
- [API reference](docs/api.md)
- [Contributing](docs/contributing.md)
- [Security](docs/security.md)
- [Architecture](docs/architecture.md)
- [Scanner interface](docs/scanner-interface.md)
- [Finding schema](docs/finding-schema.md)
- [Development guide](docs/development.md)

## License

Licensed under the MIT License. See [LICENSE](LICENSE).

## Project status

Initial release (0.1.0). The core model, scan engine, all six scanners, reporting
(terminal/JSON/Markdown/SARIF), the `sentinel` CLI, the self-hosted HTTP API server, and the
web dashboard are implemented and covered by the test suite. See the per-scanner and
per-component limitations noted throughout [docs/](docs/).
