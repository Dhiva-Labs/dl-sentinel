# Fixture conventions

Fixtures under this directory are shared, cross-cutting sample inputs used by
`tests/integration/`, `tests/e2e/`, and `tests/security/`. They exist so
those tests — and eventually every scanner — have a common, deliberately
crafted target to scan, without depending on real-world code or credentials.

## Directories

- `vulnerable-app/` — one small, deliberately insecure sample project.
  Every scanner category (secrets, dependencies, source, infra, api,
  smart-contract) should find at least one issue in it. See the file-by-file
  breakdown below.
- `clean-app/` — a small counterpart with none of those problems: the same
  shape of project, but using the safe equivalent of every pattern
  `vulnerable-app` plants (env-var config instead of hardcoded credentials,
  parameterized queries, non-root containers, resource limits, auth on every
  endpoint, checks-effects-interactions in Solidity, current-ish pinned
  dependency versions). Used as a negative control: scanners must stay quiet
  on it.
- `malformed/` — broken, empty, or otherwise degenerate inputs. Nothing in
  here should ever crash a scanner or the engine; at most it should be
  skipped or reported as unparseable.

Both `vulnerable-app/` and `clean-app/` are intentionally tiny (tens of
lines per file). They are pattern targets for scanners to match against, not
realistic applications — do not grow them into one.

## Secret fixture rules (binding)

Every credential-shaped value committed anywhere under `tests/` — here or in
a scanner's own `test/fixtures/` — must be:

1. **Synthetic.** It must not be, or resemble by coincidence, a live
   credential for any real system.
2. **Obviously fake on inspection**, while staying **format-realistic**
   enough that a pattern-matching scanner still recognizes it as the kind of
   thing it looks for. Two ways to get there, in order of preference:
   - Use a **vendor-documented example value** where the vendor publishes
     one. E.g. AWS's own docs use `AKIAIOSFODNN7EXAMPLE` /
     `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` as the canonical example
     access key pair — use those, not an invented look-alike.
   - Otherwise, **embed an `EXAMPLE`, `FAKE`, or `TEST` marker** directly in
     the value itself (not just in a comment beside it), e.g.
     `ghp_EXAMPLEEXAMPLEEXAMPLE0000000000000000`,
     `npm_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE00`. A private key block's
     base64 body should spell out `FAKEKEY` / `EXAMPLE` using only
     base64-safe characters rather than containing plausible random-looking
     data.
3. **No real hostnames or email addresses of real people or organizations.**
   Use the reserved `.example` / `.invalid` TLDs (e.g. `db.internal.example`,
   `https://example.invalid/...`) or obviously fictional names
   (`dhiva-labs-fixture`). Never a real company's domain.
4. **Registered, not just planted.** Every fake value embedded in
   `vulnerable-app/` that a redaction or security test depends on is listed
   in `tests/support/planted-secrets.ts` with its exact value and home file.
   That registry — not this document — is the source of truth for "what
   secrets exist in the fixture tree"; keep it in sync with the fixture
   files. `tests/security/redaction.test.ts` greps the fixture tree for
   patterns that would indicate a value doesn't follow rule 2 (e.g. an
   `AKIA` key not ending in `EXAMPLE`) and fails the build if one slips in.

## Relationship to scanner-local fixtures

Each scanner package will keep its own positive/negative fixture pairs under
`scanners/<id>/test/fixtures/` (see `docs/scanner-interface.md` — one
positive fixture per rule that triggers it, one negative fixture that looks
similar but must not). Those are unit-level: small, single-rule, owned by
the scanner's branch.

The fixtures here are integration-level: a whole small project that
exercises many rules across many scanners at once, used to prove
cross-cutting behavior (file discovery, matcher include/exclude, redaction,
fingerprint stability, end-to-end CLI exit codes) rather than any single
rule's logic. Scanner test suites are welcome to import
`tests/support/planted-secrets.ts` if they want to assert their rule fires
on one of these exact values, but they are not required to — their own
fixtures under `scanners/<id>/test/fixtures/` must still follow the same
secret conventions described above.

## Naming rules

- Directories: lowercase, kebab-case, self-describing (`vulnerable-app`,
  `clean-app`, `malformed`).
- Files inside `vulnerable-app/` and `clean-app/` use the real, conventional
  name a scanner expects to find (`.env`, `Dockerfile`, `docker-compose.yml`,
  `openapi.yaml`, `go.mod`, `Cargo.lock`, etc.) so glob-based
  `supportedFiles` patterns match them the way they'd match a real repo.
- Files inside `malformed/` are named after the defect they demonstrate
  (`invalid.json`, `invalid.yaml`, `empty.txt`, `binary.bin`,
  `deeply-nested.json`, `truncated-dockerfile/Dockerfile`), not after any
  scanner.

## The `.gitignore` override in `vulnerable-app/`

The repo-root `.gitignore` excludes `.env` / `.env.*` everywhere (correctly —
real secrets must never be committed). `vulnerable-app/.env` is a planted,
synthetic fixture that scanner and integration tests need present on disk,
so `vulnerable-app/.gitignore` narrowly negates just that pattern
(`!.env`, `!.env.*`) for this one directory. It does not un-ignore anything
else. If a future fixture needs another normally-ignored filename, prefer
extending that local override (or adding a similarly scoped one) over
editing the root `.gitignore`, which is owned by the lead branch.

## Runtime-generated inputs

Inputs that only make sense generated at test time — an oversized file to
exercise `maxFileSizeBytes`, a symlink to prove the engine never follows one
— must be created under `os.tmpdir()` inside the test that needs them and
cleaned up afterward. Never commit a generated symlink or a large binary
fixture here.
