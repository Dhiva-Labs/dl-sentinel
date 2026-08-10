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

Each scanner package currently contains only an interface stub in this codebase — see
[docs/scanners.md](docs/scanners.md) for what's fixed by contract today versus what's still in
progress.

## Quick start

Prerequisites: Node.js 20 or later, and npm.

```bash
git clone https://github.com/Dhiva-Labs/dl-sentinel.git
cd dl-sentinel
npm install
npm run build
npm test
```

Once the CLI is implemented (see [docs/cli.md](docs/cli.md); `apps/cli` is currently a stub):

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

Early development. `@dl-sentinel/core` and `@dl-sentinel/reporting` are implemented and tested;
the engine, all six scanners, the CLI, the API server, and the dashboard are under active
development and currently contain only interface stubs.
