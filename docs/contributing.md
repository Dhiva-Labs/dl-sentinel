# Contributing

Thanks for considering a contribution to DL Sentinel. This page covers setup, conventions, how to
add a scanner, and what's expected of a pull request.

## Getting set up

```bash
git clone https://github.com/Dhiva-Labs/dl-sentinel.git
cd dl-sentinel
npm install
npm run build
npm test
```

Useful day-to-day commands (see [Development guide](development.md) for the full list):

```bash
npm run build        # tsc -b: builds + typechecks every package (project references)
npm test              # vitest run: all unit/integration tests
npm run format        # prettier --write
npm run lint          # prettier --check + build
```

Continuous integration runs a format check, build, and the full test suite on every push and pull
request against `main` (`.github/workflows/ci.yml`); a pull request is expected to pass all three
locally before it's opened.

## Repository layout

DL Sentinel is an npm workspaces monorepo: `apps/*` (CLI, API server, dashboard), `packages/*`
(core types, engine, reporting), and `scanners/*` (one package per scanner). See
[Architecture: monorepo layout](architecture.md) for the full tree and the reasoning behind it,
and the table in the [README](../README.md) for a quick-reference summary.

## Coding conventions

From [Development guide](development.md):

- ESM everywhere. Relative imports must end in `.js` (NodeNext module resolution), for example
  `import { x } from './util.js'`, even though the source file is `util.ts`.
- Prefer `import type { ... }` for type-only imports.
- Strict TypeScript is on, including `noUncheckedIndexedAccess`. Avoid `any` unless narrowly
  justified with a comment.
- Tests live in `<package>/test/*.test.ts`; cross-package tests live in `tests/`. No placeholder
  or tautological tests.
- New runtime dependencies need maintainer approval and a written rationale — the project keeps
  its dependency footprint close to zero. `yaml` is the only approved runtime dependency today.
- Don't commit build output, `node_modules`, editor state, or environment files — `.gitignore`
  already covers these.
- A plain `npm install` commonly touches `package-lock.json` even when no dependency actually
  changed. If your change doesn't intentionally bump a dependency, run
  `git checkout -- package-lock.json` before committing so the diff stays focused on your change.

## Adding or changing a scanner

Every scanner is a package under `scanners/` exporting one `ScannerPlugin` object from its
`src/index.ts`: `id`, `name`, `version`, `categories`, `supportedFiles`, `rules` (`RuleMeta[]`),
and an async `scan(context)`. The full contract, including the required skeleton, is in
[Scanner interface](scanner-interface.md); a condensed authoring guide is in
[Rules: authoring a new rule](rules.md#authoring-a-new-rule). In short:

- Build findings with `createFinding()` and redact evidence with `redactEvidence()`, both from
  `@dl-sentinel/core` — there is no post-hoc redaction step.
- Follow the rule-id namespace for the scanner's area (see [Rules](rules.md#rule-id-namespaces)).
- Never execute target code: no `child_process`, no `eval`, no dynamic `import` of scanned files,
  no network calls except through an explicitly configured, off-by-default adapter.
- Ship a positive and a negative fixture per rule under `scanners/<id>/test/fixtures/`, with
  obviously fake secrets in any fixture that plants one. Secret-producing rules additionally need
  a test asserting the raw fixture value never appears in `JSON.stringify(findings)`.

## Commit style

Conventional, scoped commits:

```text
feat(engine): isolate scanner failures
test(secrets): add credential fixtures
fix(cli): correct sarif exit code
docs(api): document scan endpoints
```

Keep each commit scoped to one logical change.

## Pull request expectations

- A focused diff — only the files the change actually requires.
- Tests added for new behavior: positive, negative, and error cases where applicable.
- `npm test` and `npm run build` pass locally.
- `npm run format` applied.
- Documentation updated for any user-visible behavior change.
- A clear description of what changed and why.

## Definition of done

- Implementation complete; no stubs left in the paths the change touches.
- Unit tests added; integration tests where relevant.
- Security implications considered — redaction, no code execution, bounded input (see
  [Security](security.md)).
- `npm test` and `npm run build` pass locally; `npm run format` applied.
- Diff reviewed and `git status` clean before opening the pull request.
