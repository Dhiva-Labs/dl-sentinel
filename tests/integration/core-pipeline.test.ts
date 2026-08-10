import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  createFinding,
  createMatcher,
  defaultConfig,
  redactEvidence,
  type Finding,
} from '@dl-sentinel/core';
import {
  expectNoSecretLeak,
  fixturePath,
  listFixtureFiles,
  makeScanContext,
  PLANTED_SECRETS,
} from '../support/index.js';

const VULNERABLE_APP = fixturePath('vulnerable-app');

describe('listFixtureFiles over the real vulnerable-app tree', () => {
  const files = listFixtureFiles(VULNERABLE_APP);
  const relPaths = files.map((f) => f.relPath);

  it('walks a non-trivial real tree', () => {
    expect(files.length).toBeGreaterThan(10);
  });

  it('sees everything on disk, including files a real engine would exclude', () => {
    // "Honors nothing" — the __pycache__ placeholder and the dotfile are
    // both present in the raw walk; filtering is the matcher's job, tested
    // below, not listFixtureFiles's.
    expect(relPaths).toContain('.env');
    expect(relPaths).toContain('src/__pycache__/unsafe.cpython-311.pyc');
  });

  it('returns absolute absPath and repo-relative posix relPath with correct sizes', () => {
    const envRef = files.find((f) => f.relPath === '.env');
    expect(envRef).toBeDefined();
    expect(envRef?.absPath.endsWith('/vulnerable-app/.env')).toBe(true);
    expect(envRef?.size).toBe(readFileSync(envRef!.absPath).length);
  });

  it('is sorted and deterministic across repeated calls', () => {
    const again = listFixtureFiles(VULNERABLE_APP).map((f) => f.relPath);
    expect(again).toEqual(relPaths);
    expect(again).toEqual([...again].sort((a, b) => a.localeCompare(b)));
  });
});

describe('createMatcher include/exclude over the real vulnerable-app tree', () => {
  const files = listFixtureFiles(VULNERABLE_APP);
  const relPaths = files.map((f) => f.relPath);
  const config = defaultConfig();
  // Same composition the engine's own default excludes are documented to
  // produce: include patterns first, then excludes applied as negations —
  // createMatcher is gitignore-style, last match wins (docs/scanner-interface.md).
  const matcher = createMatcher([...config.include, ...config.exclude.map((p) => `!${p}`)]);

  it('excludes a default-ignored directory (__pycache__) — the node_modules-style case', () => {
    const pycacheFiles = relPaths.filter((p) => p.includes('__pycache__/'));
    expect(pycacheFiles.length).toBeGreaterThan(0);
    for (const p of pycacheFiles) {
      expect(matcher(p)).toBe(false);
    }
  });

  it('includes dotfiles like .env by default — DEFAULT_EXCLUDES has no dotfile rule', () => {
    expect(matcher('.env')).toBe(true);
  });

  it('includes ordinary tracked source, config, and infra files', () => {
    for (const p of [
      'src/unsafe.js',
      'src/unsafe.py',
      'contracts/Vulnerable.sol',
      'config/settings.yml',
      'Dockerfile',
      'docker-compose.yml',
      'openapi.yaml',
      'terraform/main.tf',
      'k8s/deployment.yaml',
    ]) {
      expect(relPaths).toContain(p);
      expect(matcher(p)).toBe(true);
    }
  });

  it('the matcher result matches applying default excludes directly to every discovered path', () => {
    // Cross-check: every path the matcher excludes is one that lives under a
    // DEFAULT_EXCLUDES directory; every path it includes does not.
    for (const p of relPaths) {
      const underExcludedDir = config.exclude.some((pattern) => createMatcher([pattern])(p));
      expect(matcher(p)).toBe(!underExcludedDir);
    }
  });
});

describe('makeScanContext built from the real vulnerable-app tree', () => {
  it('builds a usable ScanContext that can read real files', async () => {
    const files = listFixtureFiles(VULNERABLE_APP);
    const context = makeScanContext(VULNERABLE_APP, files);

    expect(context.rootDir).toBe(VULNERABLE_APP);
    expect(context.files).toBe(files);
    expect(context.signal.aborted).toBe(false);
    expect(context.config).toEqual({});

    const envRef = files.find((f) => f.relPath === '.env');
    expect(envRef).toBeDefined();
    const content = await context.readFile(envRef!);
    expect(content).toContain('DATABASE_URL');
  });

  it('passes through an explicit config section', () => {
    const context = makeScanContext(VULNERABLE_APP, [], { enabled: false, allowlist: ['x'] });
    expect(context.config).toEqual({ enabled: false, allowlist: ['x'] });
  });
});

describe('redactEvidence over every planted secret, driven by the shared registry', () => {
  const files = listFixtureFiles(VULNERABLE_APP);
  const fileContents = new Map<string, string>();
  for (const file of files) {
    fileContents.set(file.relPath, readFileSync(file.absPath, 'utf8'));
  }

  it('sanity check: every registered secret actually appears in its named fixture file', () => {
    for (const secret of PLANTED_SECRETS) {
      const content = fileContents.get(secret.file);
      expect(content, `fixture file not found: ${secret.file}`).toBeDefined();
      expect(
        content?.includes(secret.value),
        `planted secret ${secret.id} not found in ${secret.file}`,
      ).toBe(true);
    }
  });

  it('redacts every line containing a planted secret, anywhere in the fixture tree, with no residue', () => {
    for (const secret of PLANTED_SECRETS) {
      let sawAtLeastOneLine = false;
      for (const content of fileContents.values()) {
        const lines = content.split('\n').filter((line) => line.includes(secret.value));
        for (const line of lines) {
          sawAtLeastOneLine = true;
          const redacted = redactEvidence(line, [secret.value]);
          expect(redacted, `${secret.id} leaked through redactEvidence`).not.toContain(
            secret.value,
          );
        }
      }
      expect(sawAtLeastOneLine, `no line in the fixture tree contained ${secret.id}`).toBe(true);
    }
  });

  it('expectNoSecretLeak passes for findings built from redacted evidence', () => {
    const findings: Finding[] = PLANTED_SECRETS.map((secret) =>
      createFinding({
        ruleId: 'S000',
        title: 'planted secret probe',
        description: 'Synthetic finding built to exercise expectNoSecretLeak.',
        severity: 'critical',
        confidence: 'high',
        category: 'secrets',
        file: secret.file,
        evidence: redactEvidence(`value=${secret.value}`, [secret.value]),
        recommendation: 'n/a',
        references: [],
        scanner: 'core-pipeline-test',
      }),
    );
    expectNoSecretLeak(
      findings,
      PLANTED_SECRETS.map((s) => s.value),
    );
  });
});

describe('fingerprint stability across two identical walks', () => {
  function findingsFromWalk(): Finding[] {
    return listFixtureFiles(VULNERABLE_APP).map((file) =>
      createFinding({
        ruleId: 'C001',
        title: 'fixture walk finding',
        description: 'Synthetic finding derived from a fixture walk.',
        severity: 'info',
        confidence: 'low',
        category: 'other',
        file: file.relPath,
        evidence: `size=${file.size}`,
        recommendation: 'n/a',
        references: [],
        scanner: 'core-pipeline-test',
      }),
    );
  }

  it('produces identical ids, in identical order, across two independent walks', () => {
    const first = findingsFromWalk();
    const second = findingsFromWalk();
    expect(first.length).toBeGreaterThan(0);
    expect(second.map((f) => f.id)).toEqual(first.map((f) => f.id));
    expect(second.map((f) => f.file)).toEqual(first.map((f) => f.file));
  });

  it('ids are unique per file — no accidental collisions', () => {
    const ids = findingsFromWalk().map((f) => f.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});
