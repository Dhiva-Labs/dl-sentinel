# DL Sentinel GitHub Action

Scan a pull request with [DL Sentinel](../../README.md) and report **only the findings the PR
introduces** — as a sticky PR comment, a SARIF file for code scanning, and a Step Summary.

The scan runs entirely on the runner. The action's **only** network call is to the GitHub REST
API to publish the PR comment; it never uploads your source anywhere (see
[Standalone / offline](#standalone--offline)).

## What it does

1. Runs the default DL Sentinel engine over the checked-out tree (honoring an in-repo
   `sentinel.yml`).
2. Determines a **baseline** of pre-existing findings and reports only what's new (see
   [Only new findings](#only-new-findings)).
3. Writes a **SARIF** file of the new findings (`sarif_file`, default `sentinel-results.sarif`).
4. Appends a concise Markdown summary to the **Step Summary**.
5. On a `pull_request` event with a token, creates or updates a **sticky PR comment**.
6. Sets **outputs** and **fails the check** (exit 1) when a new finding hits the `fail_on`
   severities.

## Usage

```yaml
name: DL Sentinel
on:
  pull_request:

permissions:
  contents: read
  pull-requests: write # sticky PR comment
  security-events: write # SARIF upload (optional)

jobs:
  sentinel:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Base-diff mode: check out the base tree so only PR-introduced findings are reported.
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.base.sha }}
          path: .sentinel-base

      # Built from source: this is a workspace monorepo whose action entry
      # imports its sibling packages, so there is no bundled, self-contained
      # dist/ to reference as `uses:` yet. Pin `ref:` to a reviewed tag/commit.
      - uses: actions/checkout@v4
        with:
          repository: Dhiva-Labs/dl-sentinel
          ref: main
          path: .sentinel-tool
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - working-directory: .sentinel-tool
        run: npm ci && npm run build

      - run: node .sentinel-tool/apps/action/dist/main.js
        env:
          INPUT_PATH: .
          INPUT_BASE_PATH: .sentinel-base
          INPUT_FAIL_ON: critical,high
          GITHUB_TOKEN: ${{ github.token }}

      - if: always()
        continue-on-error: true
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: sentinel-results.sarif
```

A ready-to-copy version lives at [`examples/pull-request.yml`](examples/pull-request.yml).

## Inputs

Inputs are declared in [`action.yml`](action.yml), so they work as `with:` keys whenever this
is consumed as a `uses:` action. When running it directly as a Node program (the usage above),
pass each one as the matching `INPUT_` environment variable — `path` → `INPUT_PATH`,
`fail_on` → `INPUT_FAIL_ON`, and so on.

| Input        | Default                  | Description                                                                                              |
| ------------ | ------------------------ | -------------------------------------------------------------------------------------------------------- |
| `path`       | `.`                      | Directory to scan, relative to the repository root.                                                      |
| `fail_on`    | `critical,high`          | Comma-separated severities that fail the check when newly introduced.                                    |
| `scanners`   | _(all)_                  | Optional comma-separated subset of scanner ids, e.g. `secrets,dependencies`.                             |
| `baseline`   | _(none)_                 | Path to a committed baseline file; only findings absent from it are reported.                            |
| `base_path`  | _(none)_                 | Directory holding the base branch tree; scanned to build an in-memory baseline.                          |
| `config`     | _(auto)_                 | Path to a `sentinel.yml`; by default an in-repo one is auto-discovered.                                  |
| `comment`    | `true`                   | Post/update a sticky PR comment (pull_request events only).                                              |
| `sarif`      | `true`                   | Write a SARIF file of the new findings.                                                                  |
| `sarif_file` | `sentinel-results.sarif` | Where to write the SARIF file.                                                                           |
| `token`      | `${{ github.token }}`    | Token used **only** to post the PR comment. Commenting is skipped if empty.                              |

## Outputs

| Output           | Description                                                        |
| ---------------- | ----------------------------------------------------------------- |
| `findings_total` | Total findings detected in the scanned tree (before baseline).    |
| `findings_new`   | Findings introduced by this pull request (after baseline).        |
| `failed`         | `true` when new findings hit the `fail_on` severities.            |

## Only new findings

A security scan of an existing repository is noisy — most findings pre-date the PR. This action
reports only what the PR **adds**, using DL Sentinel's stable finding fingerprints. It picks a
baseline from the first source available:

1. **Committed baseline (`baseline`)** — a JSON baseline file checked into the repo (generate it
   with `sentinel baseline . --output .sentinel-baseline.json`). Findings whose id is in the file
   are treated as pre-existing and hidden.
2. **Base-tree scan (`base_path`)** — the workflow checks out the base branch into a directory and
   passes it as `base_path`. The action scans that tree, builds an in-memory baseline from it, and
   reports only findings that are not present in the base. The base directory is automatically
   excluded from the head scan so it is never double-counted.
3. **Neither** — every finding is reported as new. This is the honest default: with nothing to
   compare against, the action does not pretend the tree is unchanged.

The policy / exit code and the SARIF file always reflect the **new** findings only.

> Git operations (checking out the base ref) live in the workflow YAML, not in the action. The
> action only accepts a baseline file or an already-present base directory, keeping its Node code
> free of git plumbing.

## Exit codes

| Code | Meaning                                                                 |
| ---- | ----------------------------------------------------------------------- |
| `0`  | Scan ran; no new findings at the `fail_on` severities.                  |
| `1`  | New findings at a `fail_on` severity — the check fails the PR.          |
| `2`  | Internal error (bad input, unreadable/invalid baseline, scan failure).  |

## Standalone / offline

DL Sentinel is offline-first, and this action preserves that:

- **Scanning is fully local.** The engine reads files from the runner, never executes the code it
  scans, never follows symlinks, and never uploads source anywhere.
- **The only network call is the PR comment**, to `api.github.com` (or your GHES host via
  `GITHUB_API_URL`), guarded by an explicit token. No token, not a PR, or `comment: false` ⇒ no
  network call at all. A comment failure is logged and never fails the check.
- **Secrets never leak.** Findings are redacted at creation time; the PR comment, Step Summary,
  and SARIF render only redacted fields, and the comment omits evidence entirely.
- **No new dependencies.** The action is pure Node 20 (`fetch`, `node:fs`, `node:path`) — no
  `@actions/*`, no Octokit.

## Local dry run

```bash
npm run build
GITHUB_WORKSPACE="$PWD/tests/fixtures/vulnerable-app" \
INPUT_PATH=. \
INPUT_SARIF_FILE=/tmp/out.sarif \
GITHUB_STEP_SUMMARY=/tmp/summary.md \
GITHUB_OUTPUT=/tmp/output.txt \
node apps/action/dist/main.js   # writes SARIF + summary, exits 1 (criticals present)
```
