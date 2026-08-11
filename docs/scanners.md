# Scanners

DL Sentinel ships six scanner plugins, each implementing the `ScannerPlugin` contract described
in [Scanner interface](scanner-interface.md) and registered explicitly by the apps that use them
(the CLI and the API server — the engine does not discover scanners by magic).

All six scanners are implemented and tested; 88 rules total. The rule count per scanner is
noted below; run `sentinel rules` for the live catalog.

## Secrets (`secrets`)

- **Package:** `scanners/secrets` (`@dl-sentinel/scanner-secrets`)
- **Rule id prefix:** `S` — 22 rules.
- **Category:** `secrets`
- **Purpose:** finds credential-like values — API keys, tokens, passwords — committed to tracked
  files.
- **Supported files:** `supportedFiles: []`, meaning the scanner receives every discovered text
  file rather than a restricted set of extensions.
- **Config (`scanners.secrets`):**
  - `enabled` (boolean) — whether the scanner runs at all.
  - `allowlist` (string[]) — exact strings or rule ids to suppress.
  - `ignorePaths` (string[]) — additional path patterns to skip.
- Every secret-producing rule must redact evidence with `redactEvidence()` before a finding is
  created, and its tests must assert the raw fixture secret never appears in
  `JSON.stringify(findings)`. See [Rules](rules.md#authoring-a-new-rule).

## Dependencies (`dependencies`)

- **Package:** `scanners/dependencies` (`@dl-sentinel/scanner-dependencies`)
- **Rule id prefix:** `D` — 3 rules (`D001` known-vulnerable dependency, `D002` check skipped,
  `D003` manifest without a lockfile).
- **Category:** `dependencies`
- **Purpose:** flags dependencies with known vulnerabilities across npm, pip, Go, and Cargo.
- **Data source (`scanners.dependencies.dataSource`):** `none` | `file` | `osv`.
  - `none` — the default. No advisory data is consulted; the scanner reports "not checked"
    (`D002`) rather than fabricating a result.
  - `file` — reads a locally supplied advisory file at `advisoryDbPath`.
  - `osv` — queries the OSV database over the network. This is the only network-dependent data
    source in the system and is off by default; it requires explicit opt-in. See
    [Security](security.md#network-behavior).
- **Supported files:** `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`,
  `requirements.txt`, `requirements-*.txt`, `go.mod`, `Cargo.toml`, `Cargo.lock`.

## Source code (`source`)

- **Package:** `scanners/source` (`@dl-sentinel/scanner-source`)
- **Rule id prefix:** `C`
- **Category:** `source`
- **Rule id prefix:** `C` — 10 rules (command injection, `eval`/dynamic code, SQL from strings,
  insecure deserialization, path traversal, weak password hashing, insecure randomness, disabled
  TLS verification, permissive CORS, world-writable modes).
- **Purpose:** detects insecure coding patterns in application source.
- **Supported files:** `*.js`, `*.jsx`, `*.ts`, `*.tsx`, `*.mjs`, `*.cjs`, `*.py`, `*.go`,
  `*.rb`, `*.php`, `*.java`. Rules are deterministic line heuristics tuned for precision over
  recall; per-language coverage varies by rule.

## Infrastructure (`infra`)

- **Package:** `scanners/infra` (`@dl-sentinel/scanner-infra`)
- **Rule id prefix:** `I`
- **Categories:** `docker`, `infrastructure` — findings are categorized by artifact type rather
  than there being a single category for the scanner.
- **Purpose:** checks container and infrastructure configuration: Dockerfiles, Docker Compose
  files, Kubernetes manifests, and basic Terraform.
- **Rule id prefix:** `I` — 26 rules (Dockerfile `I001`–`I006`, Compose `I010`–`I016`,
  Kubernetes `I020`–`I028`, Terraform `I030`–`I033`).
- The Docker scanner and the infrastructure scanner described in the original plan are folded
  into this one package because they share parsing and fixtures (see
  [Architecture](architecture.md#monorepo-layout)). YAML manifests are parsed with the `yaml`
  package — the project's only approved runtime dependency alongside engine config parsing.
- **Supported files:** `Dockerfile`, `Dockerfile.*`, `*.dockerfile`, `docker-compose.yml` /
  `.yaml` / `docker-compose.*.yml`, `compose.yml` / `.yaml`, `*.yml`, `*.yaml`, `*.tf`. Generic
  YAML files are inspected and skipped unless they are Kubernetes manifests or Compose files.
  The Terraform parser is a deliberately lightweight HCL reader (no expression evaluation,
  heredocs, or `dynamic` block expansion).

## API (`api`)

- **Package:** `scanners/api` (`@dl-sentinel/scanner-api`)
- **Rule id prefix:** `A`
- **Category:** `api`
- **Rule id prefix:** `A` — 10 rules (`A001`–`A010`: missing/weak auth, API key in query,
  non-HTTPS, Basic auth, unauthenticated state-changing operations, sensitive response fields,
  missing rate-limit signals, deprecated auth flows, unconstrained inputs, Postman secrets).
- **Purpose:** analyzes API definitions — OpenAPI 3.x / Swagger 2.0 documents and Postman
  collections — for security issues.
- Every finding sets `qualifier` (`confirmed` | `likely` | `potential`) to distinguish assertion
  strength, since API analysis often can't confirm exploitability from static definitions alone.
  See [Rules](rules.md#qualifier).
- **Supported files:** `openapi.{yml,yaml,json}`, `swagger.{yml,yaml,json}`,
  `*.openapi.{yml,yaml,json}`, `api-spec*.{yml,yaml,json}`, `*postman_collection*.json`, and
  generic `*.{yml,yaml,json}` files that self-identify as API definitions.

## Smart contract (`smart-contract`)

- **Package:** `scanners/smart-contract` (`@dl-sentinel/scanner-smart-contract`)
- **Rule id prefix:** `SC`
- **Category:** `smart-contract`
- **Rule id prefix:** `SC` — 17 rules (reentrancy `SC001` and cross-function reentrancy `SC013`,
  `tx.origin` auth, unchecked low-level calls, unsafe `delegatecall`, unprotected
  `selfdestruct`/initializer/mint, pre-0.8 arithmetic, floating/outdated pragma, weak randomness,
  deprecated constructs, unguarded owner setters, unprotected proxy upgrade `SC014`, unchecked
  ERC20 transfer return `SC015`, missing zero-address check `SC016`, `delegatecall` in a loop
  `SC017`).
- **Purpose:** analyzes Solidity/EVM source for risk patterns using a line-based parser (comment
  and string stripping with preserved line numbers). Findings are heuristics; confidence is set
  accordingly and never claims a contract is secure because no rule fired.
- **Contract-level model:** on top of the line parse, the scanner resolves each file into a
  contract model — same-file inheritance (functions, modifiers, and state variables from base
  contracts declared in the same file), modifier bodies, and an intra-file call graph. That is
  what lets access-control rules judge a modifier by what its body *does* rather than what it is
  *named*, and lets reentrancy analysis follow an external call and a state write across an
  internal call hop. Documented limits, all chosen to under-report rather than guess:
  - **Same file only.** A base contract or modifier reached through an `import` cannot be read. An
    applied-but-unreadable modifier is *assumed* protective, so a correctly-guarded OpenZeppelin
    contract is not reported — and neither is an incorrectly-guarded one.
  - **Linearization is most-derived-wins, left-to-right**, not exact C3. It differs from Solidity
    only when two bases declare the same member and the derived contract does not override it.
  - **Overloads resolve by name only**; call edges are name matches, not bindings.
  - **Cross-function effects are bounded at 3 call hops.**
- **Supported files:** `*.sol`.

## See also

- [Rules](rules.md) — rule-id namespaces, severity/confidence semantics, and how to author a rule.
- [Configuration](configuration.md) — the full `sentinel.yml` reference, including per-scanner
  settings.
- [Scanner interface](scanner-interface.md) — the `ScannerPlugin` contract every scanner
  implements.
