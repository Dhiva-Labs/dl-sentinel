import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { containsSecret, redactEvidence } from '@dl-sentinel/core';
import {
  fixturePath,
  listFixtureFiles,
  PLANTED_SECRETS,
  PLANTED_SECRET_VALUES,
} from '../support/index.js';

describe('redaction regression: every planted secret leaves no residue', () => {
  it('redacts each planted secret out of a synthetic evidence line individually', () => {
    for (const secret of PLANTED_SECRETS) {
      const line = `some.config.key = "${secret.value}" # trailing comment`;
      const redacted = redactEvidence(line, [secret.value]);
      expect(containsSecret(redacted, secret.value), `${secret.id} survived redaction`).toBe(false);
      expect(redacted).toContain('[REDACTED]');
    }
  });

  it('redacts every planted secret out of a single line that contains all of them at once', () => {
    const combined = PLANTED_SECRETS.map((s) => s.value).join(' | ');
    const redacted = redactEvidence(combined, PLANTED_SECRET_VALUES);
    for (const secret of PLANTED_SECRETS) {
      expect(
        containsSecret(redacted, secret.value),
        `${secret.id} survived combined redaction`,
      ).toBe(false);
    }
    expect(redacted).toContain('[REDACTED]');
  });

  it('is unaffected by unrelated secrets not present on the line (no accidental redaction)', () => {
    const line = 'this line mentions nothing sensitive at all';
    const redacted = redactEvidence(line, PLANTED_SECRET_VALUES);
    expect(redacted).toBe(line);
  });
});

describe('fixture realism guard: fixture tree must not contain "too real" secret-shaped values', () => {
  interface DenylistRule {
    id: string;
    pattern: RegExp;
    isAllowed: (match: string) => boolean;
    message: string;
  }

  const DENYLIST_RULES: readonly DenylistRule[] = [
    {
      id: 'aws-access-key-id',
      pattern: /AKIA[0-9A-Z]{16}/g,
      isAllowed: (m) => m.endsWith('EXAMPLE'),
      message: "an AWS-shaped access key id must end in EXAMPLE (AWS's own documented example)",
    },
    {
      id: 'github-token',
      pattern: /gh[pousr]_[A-Za-z0-9]{20,}/g,
      isAllowed: (m) => m.includes('EXAMPLE') || m.includes('FAKE') || m.includes('TEST'),
      message: 'a GitHub-shaped token must embed an EXAMPLE/FAKE/TEST marker',
    },
    {
      id: 'npm-token',
      pattern: /npm_[A-Za-z0-9]{20,}/g,
      isAllowed: (m) => m.includes('EXAMPLE') || m.includes('FAKE') || m.includes('TEST'),
      message: 'an npm-shaped token must embed an EXAMPLE/FAKE/TEST marker',
    },
  ];

  // Raw walk of the entire fixture tree (vulnerable-app, clean-app,
  // malformed, and this README) — the same denylist applies everywhere
  // under tests/fixtures/, not just the vulnerable-app fixture.
  const files = listFixtureFiles(fixturePath());
  const contents = files.map((f) => ({
    relPath: f.relPath,
    text: readFileSync(f.absPath, 'utf8'),
  }));

  for (const rule of DENYLIST_RULES) {
    it(`every ${rule.id}-shaped value in the fixture tree passes: ${rule.message}`, () => {
      let matchCount = 0;
      for (const { relPath, text } of contents) {
        for (const match of text.matchAll(rule.pattern)) {
          matchCount += 1;
          expect(rule.isAllowed(match[0]), `${rule.id} in ${relPath}: "${match[0]}"`).toBe(true);
        }
      }
      // Guard against the check going vacuous if the fixture is ever edited
      // to remove every example of this pattern.
      expect(
        matchCount,
        `expected at least one ${rule.id}-shaped value in the fixture tree`,
      ).toBeGreaterThan(0);
    });
  }

  it('every registered planted secret still satisfies its own denylist rule where one applies', () => {
    for (const secret of PLANTED_SECRETS) {
      for (const rule of DENYLIST_RULES) {
        for (const match of secret.value.matchAll(rule.pattern)) {
          expect(rule.isAllowed(match[0]), `${secret.id} fails ${rule.id}`).toBe(true);
        }
      }
    }
  });
});
