# Scanners

DL Sentinel ships six scanner plugins, each implementing the `ScannerPlugin` contract described
in [Scanner interface](scanner-interface.md) and registered explicitly by the apps that use them
(the CLI and the API server — the engine does not discover scanners by magic).

> Status: implementation in progress. Every scanner package listed below currently contains only
> an interface stub (`export {}`) in `scanners/<id>/src/index.ts`. Purpose, rule-id prefix, and
> category are fixed by [Architecture](architecture.md) and `packages/core/src/types.ts`; file
> globs and scanner-specific settings beyond `enabled` are only fixed today for secrets and
> dependencies, and are noted as such below.

## Secrets (`secrets`)

- **Package:** `scanners/secrets` (`@dl-sentinel/scanner-secrets`)
- **Rule id prefix:** `S`
- **Category:** `secrets`
- **Purpose:** finds credential-like values — API keys, tokens, passwords — committed to tracked
  files.
- **Supported files:** the skeleton in [Scanner interface](scanner-interface.md#skeleton)
  declares `supportedFiles: []`, meaning the scanner is intended to receive every discovered file
  rather than a restricted set of extensions.
- **Config (`scanners.secrets`):**
  - `enabled` (boolean) — whether the scanner runs at all.
  - `allowlist` (string[]) — exact strings or rule ids to suppress.
  - `ignorePaths` (string[]) — additional path patterns to skip.
- Every secret-producing rule must redact evidence with `redactEvidence()` before a finding is
  created, and its tests must assert the raw fixture secret never appears in
  `JSON.stringify(findings)`. See [Rules](rules.md#authoring-a-new-rule).

## Dependencies (`dependencies`)

- **Package:** `scanners/dependencies` (`@dl-sentinel/scanner-dependencies`)
- **Rule id prefix:** `D`
- **Category:** `dependencies`
- **Purpose:** flags dependencies with known vulnerabilities.
- **Data source (`scanners.dependencies.dataSource`):** `none` | `file` | `osv`.
  - `none` — the default. No advisory data is consulted; the scanner reports "not checked"
    rather than fabricating a result.
  - `file` — reads a locally supplied advisory file at `advisoryDbPath`.
  - `osv` — queries the OSV database over the network. This is the only network-dependent data
    source in the system and is off by default; it requires explicit opt-in. See
    [Security](security.md#network-behavior).
- **Supported files:** not finalized in the contract docs. Dependency manifests and lockfiles are
  the expected input; the exact globs will be declared by the scanner's `supportedFiles` array
  when implemented.

## Source code (`source`)

- **Package:** `scanners/source` (`@dl-sentinel/scanner-source`)
- **Rule id prefix:** `C`
- **Category:** `source`
- **Purpose:** detects insecure coding patterns in application source.
- **Supported files / config:** not finalized beyond the `enabled` flag common to every scanner.
  The contract docs do not yet specify file globs or dedicated settings for this scanner.

## Infrastructure (`infra`)

- **Package:** `scanners/infra` (`@dl-sentinel/scanner-infra`)
- **Rule id prefix:** `I`
- **Categories:** `docker`, `infrastructure` — findings are categorized by artifact type rather
  than there being a single category for the scanner.
- **Purpose:** checks container and infrastructure configuration: Dockerfiles, Docker Compose
  files, Kubernetes manifests, and basic Terraform.
- The Docker scanner and the infrastructure scanner described in the original plan are folded
  into this one package because they share parsing and fixtures (see
  [Architecture](architecture.md#monorepo-layout)). Parsing YAML-based manifests is expected to
  use the `yaml` package — the project's only approved runtime dependency alongside engine config
  parsing.
- **Supported files / config:** not finalized beyond `enabled`.

## API (`api`)

- **Package:** `scanners/api` (`@dl-sentinel/scanner-api`)
- **Rule id prefix:** `A`
- **Category:** `api`
- **Purpose:** analyzes API definitions — OpenAPI/Swagger documents and Postman collections —
  for security issues.
- This is the scanner the contract specifically calls out as required to use `qualifier`
  (`confirmed` | `likely` | `potential`) to distinguish assertion strength, since API analysis
  often can't confirm exploitability from static definitions alone. See
  [Rules](rules.md#qualifier).
- **Supported files / config:** not finalized beyond `enabled`.

## Smart contract (`smart-contract`)

- **Package:** `scanners/smart-contract` (`@dl-sentinel/scanner-smart-contract`)
- **Rule id prefix:** `SC`
- **Category:** `smart-contract`
- **Purpose:** analyzes Solidity/EVM source for risk patterns.
- **Supported files / config:** not finalized beyond `enabled`.

## See also

- [Rules](rules.md) — rule-id namespaces, severity/confidence semantics, and how to author a rule.
- [Configuration](configuration.md) — the full `sentinel.yml` reference, including per-scanner
  settings.
- [Scanner interface](scanner-interface.md) — the `ScannerPlugin` contract every scanner
  implements.
