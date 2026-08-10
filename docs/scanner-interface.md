# Scanner Interface

Every scanner is a package under `scanners/` exporting one `ScannerPlugin` object from its
`src/index.ts`. The engine discovers nothing by magic — apps import scanner packages and
register them explicitly.

## The contract

Types live in `@dl-sentinel/core` (`packages/core/src/types.ts`) and are the source of
truth. Summary:

```ts
export interface ScannerPlugin {
  id: string;                 // short stable id, e.g. "secrets" — also the config key
  name: string;               // human name, e.g. "Secrets Scanner"
  version: string;
  categories: Category[];
  supportedFiles: string[];   // repo-relative globs; [] = receive all discovered files
  rules: RuleMeta[];          // every rule the scanner can emit, statically declared
  scan(context: ScanContext): Promise<Finding[]>;
}

export interface ScanContext {
  rootDir: string;                    // absolute target root
  files: readonly FileRef[];          // pre-filtered for this scanner
  config: Record<string, unknown>;    // config.scanners[<id>] section, may be {}
  signal: AbortSignal;                // check .aborted in long loops; throw to stop
  logger: ScanLogger;                 // never log secret values
  readFile(ref: FileRef): Promise<string>;  // UTF-8; engine already excluded binaries
}
```

## Engine guarantees (what a scanner may assume)

- `files` only contains files matching the scanner's `supportedFiles` globs, minus global
  excludes, oversized files, binaries, and symlinks.
- `readFile` never returns content for a file larger than the configured cap.
- The scanner's config section is present (possibly empty) and `enabled: false` scanners
  are never invoked.
- Concurrency: scanners run concurrently with other scanners, but each scanner's `scan` is
  called exactly once per scan run.

## Scanner obligations

1. **Declare every rule** in `rules` with id, title, severity, default confidence,
   category, description, recommendation. `sentinel rules` renders this list.
2. **Use rule-id namespaces**: S secrets · D dependencies · C source · I infra · A api ·
   SC smart-contract, followed by a zero-padded number (S001).
3. **Build findings with `createFinding()`** from core so ids are stable fingerprints.
4. **Redact before creating.** `evidence` must never contain a secret value — pass line
   text through `redactEvidence(line, [matchedValue])`. There is no post-hoc redaction;
   the finding you create is what gets reported.
5. **Honor cancellation**: check `context.signal.aborted` at least once per file and throw
   (any error) to stop early; the engine treats an abort as cancellation, not failure.
6. **Never execute target code.** No `child_process`, no `eval`, no dynamic `import` of
   scanned files, no network calls except through an explicitly configured adapter that is
   off by default.
7. **Be deterministic.** Sort or otherwise stabilize output where iteration order could
   vary.
8. **Prefer precision.** A rule that floods meaningless findings is worse than no rule.
   Use `confidence` honestly; use `qualifier` (`confirmed | likely | potential`) when the
   scanner distinguishes assertion strength (required for the API scanner).

## Skeleton

```ts
import type { Finding, RuleMeta, ScanContext, ScannerPlugin } from '@dl-sentinel/core';
import { createFinding, redactEvidence } from '@dl-sentinel/core';

const rules: RuleMeta[] = [
  {
    id: 'S001',
    title: 'Hardcoded credential detected',
    severity: 'critical',
    defaultConfidence: 'high',
    category: 'secrets',
    description: 'A credential-like value appears in tracked source.',
    recommendation: 'Move the credential to an environment variable or secret manager.',
    references: [],
  },
];

async function scan(context: ScanContext): Promise<Finding[]> {
  const findings: Finding[] = [];
  for (const file of context.files) {
    if (context.signal.aborted) throw new Error('aborted');
    const text = await context.readFile(file);
    // ...match rules, then:
    // findings.push(createFinding({ ruleId: 'S001', ..., file: file.relPath,
    //   evidence: redactEvidence(lineText, [matchedValue]), scanner: secretsScanner.id }));
  }
  return findings;
}

export const secretsScanner: ScannerPlugin = {
  id: 'secrets',
  name: 'Secrets Scanner',
  version: '0.1.0',
  categories: ['secrets'],
  supportedFiles: [],
  rules,
  scan,
};
```

## Testing requirements (per rule)

- A **positive fixture** that triggers the rule, asserting rule id, severity, file, line.
- A **negative fixture** that looks similar but must NOT trigger.
- For secrets rules additionally: assert the raw secret value does not appear anywhere in
  the serialized findings (`JSON.stringify(findings)`).
- Fixtures live in `scanners/<id>/test/fixtures/`; fixture secrets must be obviously fake
  (see `tests/fixtures/README.md` conventions) while still matching realistic formats.

Scanner tests build a `ScanContext` directly (no engine needed):

```ts
import { noopLogger } from '@dl-sentinel/core';
import { readFile } from 'node:fs/promises';

function contextFor(rootDir: string, files: FileRef[]): ScanContext {
  return {
    rootDir,
    files,
    config: {},
    signal: new AbortController().signal,
    logger: noopLogger,
    readFile: (ref) => readFile(ref.absPath, 'utf8'),
  };
}
```

## Glob semantics for `supportedFiles`

Patterns are anchored to the repo-relative path; use `**/` prefixes for any-depth matching
(`'**/*.py'`, `'**/Dockerfile*'`, `'**/.env*'`). `*` stays within a path segment, `?`
matches one non-slash character, `{a,b}` expands, trailing `/` means the whole directory.
Dotfiles are matched normally. Implementation and tests: `packages/core/src/glob.ts`.
