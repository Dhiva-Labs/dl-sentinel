# DL Sentinel

[![ARM64 builds](https://github.com/Dhiva-Labs/dl-sentinel/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Dhiva-Labs/dl-sentinel/actions/workflows/ci.yml)
![Linux x64 | arm64](https://img.shields.io/badge/Linux-x64%20%7C%20arm64-informational?logo=linux&logoColor=white)
![Docker amd64 | arm64](https://img.shields.io/badge/Docker-amd64%20%7C%20arm64-informational?logo=docker&logoColor=white)
![Linux: deb | rpm | Arch](https://img.shields.io/badge/Linux-deb%20%7C%20rpm%20%7C%20Arch-informational?logo=linux&logoColor=white)
![Node 20+](https://img.shields.io/badge/node-20%2B-informational?logo=nodedotjs&logoColor=white)

DL Sentinel is a developer-focused security scanning platform by DhivaLabs. It scans a
repository for exposed secrets, vulnerable dependencies, insecure source code patterns,
container and infrastructure misconfiguration, API definition security issues, and smart-contract
risk patterns, then produces structured findings and reports.

It is built for teams that want static security scanning they can run locally or self-host,
without sending source code to a third-party service. The same local scan also runs in CI, as a
GitHub Action that checks pull requests.

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

88 rules in total (`sentinel rules` prints the live count). 79 carry a CWE mapping, and 55 of
those also carry an OWASP Top 10 (2021) category; the other 9 are hygiene or informational checks
left unmapped on purpose. See [docs/scanners.md](docs/scanners.md) and
[docs/rules.md](docs/rules.md).

## Engineering highlights

- **Attack-path correlation** — each chain rule documents the findings it needs, a bound on how
  many paths it emits, and why confidence stays `potential` unless the infrastructure graph ties
  the findings to the same service. Confidence is capped at `likely`. Seven rules, e.g.
  [`ap001-privileged-exposure.ts`](packages/attack-paths/src/rules/ap001-privileged-exposure.ts);
  tests in [`packages/attack-paths/test`](packages/attack-paths/test).
- **PR-diff GitHub Action** — scans the head tree, builds a baseline from a committed file or a
  checked-out base tree, and reports only what the PR introduced as a sticky comment, Step
  Summary and SARIF file ([`apps/action/src/scan.ts`](apps/action/src/scan.ts),
  [tests](apps/action/test)).
- **SARIF 2.1.0 output** — [`packages/reporting/src/sarif.ts`](packages/reporting/src/sarif.ts).
- **Self-hosted API with RBAC and a scan queue** — `viewer`, `operator` and `admin` roles
  ([`permissions.ts`](apps/api/src/permissions.ts)); a bounded in-process worker pool that turns
  a failed scan into a `failed` record with a sanitized error instead of crashing the server
  ([`queue.ts`](apps/api/src/queue.ts)). Role enforcement, token lifecycle and audit-log
  attribution are tested in [`rbac.test.ts`](apps/api/test/rbac.test.ts).
- **Solidity analysis without an external tool** — a hand-written parser
  ([`parser.ts`](scanners/smart-contract/src/parser.ts)) feeds a contract model with same-file
  inheritance, modifier bodies and a call graph, so access-control rules look at what a
  modifier does. It has not been compared against other tools such as Slither.
- **Cross-architecture CI** — the suite, the `.deb`/`.rpm`/Arch packages and the Docker stack
  are built and exercised on x64 and arm64 ([`ci.yml`](.github/workflows/ci.yml)).

At this commit the suite is 141 test files and 1531 tests (`npm test`). Many scanner rules have
a small positive and negative fixture pair, so the number of fixture files on disk is much
larger than the number of test files.

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
- **Attack paths** — `sentinel scan --paths` correlates findings (and the graph) into candidate
  chains, such as a committed AWS key beside a public bucket, or a privileged container that is
  also host-networked. Candidates for review, never claims of exploitability. See
  [docs/attack-paths.md](docs/attack-paths.md).
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

## Platforms

DL Sentinel runs on **Linux x64 and Linux arm64 (aarch64)**. Everything that ships is plain
JavaScript, so every way to run it behaves the same on both:

- **From source** (above): Node.js 20 or later. The only runtime dependency is `yaml`, which is
  pure JavaScript; the native binaries in the dev toolchain (esbuild, rollup) have arm64
  builds.
- **Debian package** (`dlsentinel`): `Architecture: all`. It contains one bundled JavaScript
  file and depends on the distribution's own `nodejs (>= 18)`, so it bundles no `node` binary
  and no native modules, and the same `.deb` installs on amd64 and arm64.
- **Fedora, RHEL and openSUSE** (`dlsentinel-<version>-1.noarch.rpm`) and **Arch Linux**
  (`dlsentinel-<version>-1-any.pkg.tar.zst`): the same files as the `.deb`, repackaged, with a
  dependency on the distribution's `/usr/bin/node` (Fedora's `nodejsNN-bin`, Arch's `nodejs`).
  The AUR recipe `dlsentinel-bin` (`dlsentinel-bin-<version>-aur.tar.gz`, PKGBUILD + .SRCINFO)
  repackages the release's `.deb`. From the next release on these files, and the `.deb` as
  `dlsentinel_<version>_all.deb`, are attached to each GitHub release:

  ```bash
  sudo dnf install ./dlsentinel-<version>-1.noarch.rpm                            # Fedora, RHEL
  sudo zypper install --allow-unsigned-rpm ./dlsentinel-<version>-1.noarch.rpm    # openSUSE
  sudo pacman -U ./dlsentinel-<version>-1-any.pkg.tar.zst                         # Arch
  ```

  The `.rpm` is unsigned and does not pin a Node.js version (Fedora names its Node.js packages
  per major version); the bundle needs Node.js 18 or later, which current Fedora, openSUSE
  Tumbleweed and Arch all ship. No AppImage or Flatpak: this is a command-line tool.
- **Docker / Compose** ([docs/deployment.md](docs/deployment.md)): `docker compose up` builds
  the image for the host's architecture (the `node:20-alpine` base is multi-arch). No image is
  published; you build it where it runs.

CI runs the whole test suite on Ubuntu 24.04 (x64) and Ubuntu 24.04 arm64. On both it also
builds the `.deb` and checks that the files are byte-for-byte identical, installs each build on
each architecture (including the x64-built package on arm64, and the reverse) and scans the
test fixtures with the installed command, builds the Docker image natively, starts the compose
stack and runs a scan through the HTTP API. The `.rpm` is installed on Fedora and openSUSE
Tumbleweed (x64 and arm64) and the Arch package on Arch Linux (x64; Arch has no official arm64
image, so arm64 gets a static check), and each runs the same command checks and fixture scans as
the `.deb` against that distribution's own Node.js; the AUR recipe is built with `makepkg` and
put through the same checks. Windows is not covered.

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
| `packages/attack-paths` | `@dl-sentinel/attack-paths` | Correlates findings into candidate attack chains |
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
- [Attack paths](docs/attack-paths.md)
- [Plugins](docs/plugins.md)
- [Contributing](docs/contributing.md)
- [Releasing](docs/releasing.md)
- [Security](docs/security.md)
- [Architecture](docs/architecture.md)
- [Scanner interface](docs/scanner-interface.md)
- [Finding schema](docs/finding-schema.md)
- [Development guide](docs/development.md)

## Sponsors

Dhiva Labs is an independent, self-funded lab. [Sponsorships](https://github.com/sponsors/Dhiva-Labs) help bring this project and the rest of Dhiva Labs to every platform, iPhone and Mac included.

[![Sponsor Dhiva Labs](https://img.shields.io/badge/Sponsor-Dhiva%20Labs-ea4aaa?logo=githubsponsors&logoColor=white)](https://github.com/sponsors/Dhiva-Labs)

Monthly sponsors at $10 and up are listed here:

<!-- sponsors -->
*Be the first: [sponsor Dhiva Labs](https://github.com/sponsors/Dhiva-Labs).*
<!-- sponsors -->

## License

Licensed under the MIT License. See [LICENSE](LICENSE).

## Project status

Version 0.1.0, the first and only release so far. It is early software: the GitHub release
carries no packaged files yet (see [Platforms](#platforms)), and the Action is pinned by tag.
The scan engine and six scanners, reporting, baselines and suppressions, the `sentinel` CLI, the
GitHub Action, the self-hosted API server (async scan queue, schedules, history and trends,
RBAC, notifications), the web dashboard, the infrastructure graph and plugin loading are
implemented and covered by the test suite.

Limits to know about:

- The scanners are static pattern analyzers, not provers. Rules are written to under-report
  rather than guess, and findings carry severity and confidence, but false-positive and
  false-negative rates have not been measured against a benchmark corpus.
- The Solidity parser is hand-written and has not been compared against other tools.
- There is no third-party security audit, and the project has no known external users yet.
- Linux x64 and arm64 only; Windows and macOS are not tested.
- Attack paths are candidates for review, not statements that something is exploitable.
