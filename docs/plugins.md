# Plugins (external scanners)

A **plugin** is a scanner that ships outside this repository. It implements exactly the same
contract as a built-in scanner — [Scanner Interface](scanner-interface.md) — and is loaded at
runtime from an operator-supplied path or package name.

If you are adding a scanner *inside* DL Sentinel, read [Scanner Interface](scanner-interface.md)
instead; this page covers the packaging, loading and trust rules that apply to third-party ones.

## The trust boundary (read this first)

**A plugin is code. Loading one runs it, with everything this process can reach.** DL Sentinel
does not sandbox plugins: a loaded plugin can read any file the scanner user can read, open
network connections, and write anywhere on disk. It runs alongside a tool that is routinely
pointed at repositories full of credentials.

That leads to three binding rules:

1. **Only the operator can name a plugin.** Plugins load from the CLI's `--plugin` flag or the
   API server's `SENTINEL_PLUGINS` environment variable — nothing else.
2. **Configuration can never load a plugin.** A `plugins:` key in `sentinel.yml` is ignored with
   a warning, and that holds even for an explicit `--config <file>`. Config files travel inside
   the repositories being scanned; if config could name a plugin, scanning an untrusted
   repository would execute code chosen by that repository. **The scanned repository can never
   introduce a plugin.**
3. **Review before you load.** Treat adding a plugin exactly like adding a dependency to your
   build: read it, pin it, and only load ones you or someone you trust has reviewed. "It only
   scans" is not a property the tool can enforce for you.

Everything else on this page assumes those three rules.

## Naming

Publish a plugin as `dl-sentinel-plugin-<name>` (or `@your-scope/dl-sentinel-plugin-<name>`).
The convention makes plugins findable and makes it obvious in a dependency list that a package
will be loaded into the scanner.

Keep the plugin's `id` short, stable and distinct — it is the key used in `sentinel.yml`'s
`scanners:` section, in `--scanners`, in every finding's `scanner` field, and in report output.
An id that collides with a built-in (`secrets`, `dependencies`, `source`, `infra`, `api`,
`smart-contract`) or with another loaded plugin is rejected; a plugin can never shadow a
built-in scanner.

Rule ids should be namespaced with a prefix of your own (`ACME001`, not `S001`) so they never
collide with the built-in namespaces documented in [Rules](rules.md#rule-id-namespaces).

## A minimal plugin

A plugin module's **default export** is a `ScannerPlugin`. Depend on `@dl-sentinel/core` for the
types and helpers (`createFinding`, `redactEvidence`); nothing else about the host is available
to you.

```ts
// dl-sentinel-plugin-acme/src/index.ts
import type { Finding, RuleMeta, ScanContext, ScannerPlugin } from '@dl-sentinel/core';
import { createFinding, redactEvidence } from '@dl-sentinel/core';

const ACME001: RuleMeta = {
  id: 'ACME001',
  title: 'Acme deploy token in tracked source',
  severity: 'critical',
  defaultConfidence: 'high',
  category: 'secrets',
  description: 'An Acme deploy token (acme_dt_…) appears in a tracked file.',
  recommendation: 'Revoke the token and move it to your secret manager.',
  references: ['https://example.com/acme/docs/tokens'],
};

const rules: RuleMeta[] = [ACME001];

const TOKEN = /\backme_dt_[A-Za-z0-9]{24}\b/g;

async function scan(context: ScanContext): Promise<Finding[]> {
  const findings: Finding[] = [];
  for (const file of context.files) {
    if (context.signal.aborted) throw new Error('aborted');
    const text = await context.readFile(file);
    for (const [index, line] of text.split('\n').entries()) {
      for (const match of line.matchAll(TOKEN)) {
        findings.push(
          createFinding({
            ruleId: ACME001.id,
            title: ACME001.title,
            description: ACME001.description,
            severity: ACME001.severity,
            confidence: ACME001.defaultConfidence,
            category: ACME001.category,
            file: file.relPath,
            line: index + 1,
            // Never put the secret itself in evidence.
            evidence: redactEvidence(line, [match[0]]),
            recommendation: ACME001.recommendation,
            references: ACME001.references ?? [],
            scanner: 'acme',
          }),
        );
      }
    }
  }
  return findings;
}

const plugin: ScannerPlugin = {
  id: 'acme',
  name: 'Acme Secrets Scanner',
  version: '1.0.0',
  categories: ['secrets'],
  supportedFiles: [], // [] = every discovered file
  rules,
  scan,
};

export default plugin;
```

Ship it as ESM (`"type": "module"`) with the built entry point as the package's `main`/`exports`,
or point `--plugin` straight at a built file. The same obligations a built-in scanner has apply
in full — redaction, honest confidence, cancellation, no execution of scanned code — see
[Scanner obligations](scanner-interface.md#scanner-obligations).

### What the loader checks

Before a plugin is registered, its default export is validated: non-empty `id`/`name`/`version`,
`categories` and `supportedFiles` arrays of strings, a `rules` array whose entries carry string
`id`/`title`/`description`/`recommendation`/`category` and a valid `severity` and
`defaultConfidence`, and a `scan` function. Anything else is refused with a message naming the
spec and the offending field. Validation catches mistakes, not malice — it says nothing about
what `scan` will do when it runs.

## Loading a plugin

### CLI

`--plugin <path-or-package>` is accepted by `scan`, `baseline`, `rules` and `plugins`, and may be
repeated. A spec that starts with `.` or `/`, or that ends in `.js`/`.mjs`/`.cjs`, is resolved as
a file path relative to the current directory; anything else is resolved as an installed package.

```bash
sentinel scan . --plugin ./plugins/acme/dist/index.js
sentinel scan . --plugin dl-sentinel-plugin-acme --plugin @acme/dl-sentinel-plugin-infra
```

Plugins register after the built-ins, in flag order. A failure to load — unresolvable spec, a
module that throws on import, a malformed plugin, a duplicate or built-in id — exits `64` before
any scanning starts.

A package name resolves the way any Node import does: from the scanner's own installation, not
from the directory being scanned. If the plugin is installed somewhere the scanner cannot resolve
(a project-local `node_modules` while `sentinel` runs from a global install), point `--plugin` at
its built file instead. `sentinel plugins` prints the path that was actually imported, which is
the quickest way to confirm you got the one you meant.

### API server

`SENTINEL_PLUGINS` takes a comma-separated list of the same specs:

```bash
SENTINEL_PLUGINS=dl-sentinel-plugin-acme,/opt/sentinel/plugins/infra.mjs sentinel-api
```

They are loaded during startup. If any spec fails to load, **the server refuses to start**
(stderr message, exit `1`) rather than serve with fewer scanners than the operator configured —
a scanner silently missing is a clean report for a check that never ran.

Embedders calling `createServer()` directly pass already-constructed plugins as
`ServerOptions.plugins` instead; that path performs the same validation but no dynamic import.

## Trying a plugin out

`sentinel plugins` loads plugins and reports what they would contribute, without scanning
anything:

```bash
$ sentinel plugins --plugin ./plugins/acme/dist/index.js

acme Acme Secrets Scanner 1.0.0
  rules       1 rule
  categories  secrets
  source      /home/dev/plugins/acme/dist/index.js

Loaded 1 plugin. Plugins run with the scanner's privileges — only load code you trust.
```

Use `--format json` for `[{ id, name, version, categories, rules, spec, source }]`. Check
`source` when a spec is ambiguous: it is the file or package that was actually imported.

Then confirm the rules land where you expect, and run a scan:

```bash
sentinel rules --plugin ./plugins/acme/dist/index.js            # plugin rules after built-ins
sentinel rules --plugin ./plugins/acme/dist/index.js --scanners acme --format json
sentinel scan ./fixture --plugin ./plugins/acme/dist/index.js
```

Note that `sentinel plugins` still *imports* the module, so it executes top-level code. It is a
dry run in the sense that nothing is scanned, not in the sense that nothing ran.

## How a plugin shows up everywhere else

Once registered, a plugin is indistinguishable from a built-in:

- **Rules** — listed by `sentinel rules` and `GET /api/rules`, tagged with the plugin's id.
- **Selection** — `--scanners <id>` and the API's `"scanners": [...]` accept the plugin's id.
- **Configuration** — `scanners.<id>` in `sentinel.yml` configures it, and
  `scanners.<id>.enabled: false` disables it. (Config can *configure* a plugin; it can never
  *load* one.)
- **Findings and reports** — its findings carry `scanner: "<id>"`, are deduplicated, sorted,
  suppressed, baselined and rendered like any other, in every format.
- **Policy and exit codes** — its findings count toward `policy.failOn`, so a plugin's `high`
  finding fails a build exactly as a built-in's would.
- **Failure isolation** — a plugin that throws during `scan` is recorded in `report.errors` and
  the rest of the scan continues; a plugin that fails to *load* is fatal, because that is an
  operator configuration error rather than a scan result.

## Testing your plugin

Test it as its own package, the way the built-in scanners are tested
([Testing requirements](scanner-interface.md#testing-requirements-per-rule)): a positive and a
negative fixture per rule, plus an assertion that no evidence field ever contains a raw secret.

Two extra checks are worth having, because they cover the plugin boundary itself:

- Import your built entry point and assert its default export passes `validateScannerPlugin`
  from `@dl-sentinel/engine` — the exact check the loader runs.
- Run `sentinel plugins --plugin <your build output> --format json` in CI and assert the id,
  version and rule count. It catches the packaging mistakes unit tests never see: a missing
  default export, an entry point that does not resolve, a build that never ran.
