# Security

This page describes the security model *of DL Sentinel itself* — the guarantees the tool makes
about how it treats the code and secrets it scans. For rule-level detail behind specific findings,
see [Scanners](scanners.md) and [Rules](rules.md).

> Status: the redaction and fingerprinting utilities described below (`redactEvidence`,
> `createFinding`) are implemented today in `@dl-sentinel/core`. The engine and scanners that are
> required to use them, and the API server described in the storage and network sections, are
> still in progress. The guarantees themselves are binding design principles fixed in
> [Architecture](architecture.md#security-posture-binding), not aspirational goals.

## Read-only scanning

DL Sentinel never executes the code it scans and never modifies the scan target. A scanner reads
files only through the engine-provided `readFile()` and must not shell out (`child_process`),
`eval`, dynamically `import` a scanned file, or otherwise run target code. File discovery never
follows symlinks, so a target cannot use a crafted link to redirect scanning outside its own tree.

## Secret redaction invariant

Findings never contain an unredacted secret value. Any evidence string a scanner builds from
matched text is passed through `redactEvidence(text, [matchedValue])` from `@dl-sentinel/core`,
which replaces every occurrence of every matched value with `[REDACTED]` before the finding is
created — there is no post-hoc redaction step; the finding a scanner creates is what gets
reported. The finding's `id` is a fingerprint computed over already-redacted fields (see
[Finding schema](finding-schema.md#fingerprint-id)), so no secret material enters even the id.
Every secret-producing rule's tests are required to assert that the raw fixture value never
appears anywhere in `JSON.stringify(findings)`. Reports (terminal, JSON, Markdown, SARIF), the API
server, the dashboard, and logs all render findings as-is — none of them are permitted to add
unredacted data of their own.

## What the API server stores, and where

The self-hosted API server persists its data — scans, findings, and a JSONL audit log — under a
local data directory, `.dl-sentinel/`, rather than anywhere external. That directory is excluded
from scanning by default and from version control (see `.gitignore` and the default excludes in
[Configuration](configuration.md#default-excludes)), since it holds the server's own state rather
than source to be analyzed.

## Network behavior

DL Sentinel is offline by default. The only network-capable component is the dependency scanner's
OSV data source (`scanners.dependencies.dataSource: osv`), and it only runs when explicitly
configured — the default is `none`. When no data source is configured, the dependency scanner
reports findings as "not checked" rather than fabricating vulnerability data; it never invents an
advisory it did not receive from its configured source. Network-dependent data sources in general
sit behind explicit, opt-in adapters, which keeps scans deterministic: the same input always
produces the same findings.

## Additional principles

From the project's binding security posture:

- Never log secret values.
- Never execute repository scripts.
- Never follow symlinks during discovery.
- Never upload scanned source anywhere.
- Never claim a vulnerability is exploitable without verification.
- Never claim a target is secure solely because no rule fired.
- Prefer least privilege, explicit permissions, bounded memory, deterministic output, and audit
  logs.

## Reporting a vulnerability in DL Sentinel

If you find a security vulnerability in DL Sentinel itself, do not open a public issue. Open a
private security advisory on the repository instead, so it can be triaged before any details are
public: [github.com/Dhiva-Labs/dl-sentinel/security/advisories/new](https://github.com/Dhiva-Labs/dl-sentinel/security/advisories/new).
