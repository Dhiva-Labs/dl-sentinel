import { describe, expect, it } from 'vitest';
import type { FileRef } from '@dl-sentinel/core';
import secretsScanner from '@dl-sentinel/scanner-secrets';
import {
  fileRef,
  FIXTURE_ROOT,
  listTextFiles,
  makeContext,
  recordingLogger,
  scanFixtures,
} from './helpers.js';
import { ALL_FIXTURE_SECRETS } from './rule-cases.js';
// The redaction backstop is internal to the scan pass, so it is reached
// directly: no public input can make a well-behaved rule leak, which is
// exactly why the last line of defence needs its own test.
import { leaksSecret } from '../src/scan.js';

const GITHUB_TOKEN = 'ghp_EXAMPLEEXAMPLEEXAMPLE0000000000000000';
const SECOND_GITHUB_TOKEN = 'ghp_FAKEFAKEFAKEFAKE111111111111111111111';
const NPM_TOKEN = 'npm_EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE00';

describe('multiple secrets on one line', () => {
  it('reports each occurrence separately', async () => {
    const findings = await scanFixtures(['behaviour/two-tokens.txt']);
    expect(findings).toHaveLength(2);
    expect(findings.map((finding) => finding.ruleId)).toEqual(['S003', 'S003']);
    expect(findings[0]?.line).toBe(2);
    expect(findings[1]?.line).toBe(2);
    expect(findings[0]?.column).not.toBe(findings[1]?.column);
    // Distinct fingerprints, so the engine's dedupe keeps both.
    expect(findings[0]?.id).not.toBe(findings[1]?.id);
  });

  it('redacts every secret on the line out of every finding on that line', async () => {
    const findings = await scanFixtures(['behaviour/two-tokens.txt']);
    for (const finding of findings) {
      expect(finding.evidence).not.toContain(GITHUB_TOKEN);
      expect(finding.evidence).not.toContain(SECOND_GITHUB_TOKEN);
      expect(finding.evidence).toBe('tokens=[REDACTED],[REDACTED]');
    }
  });
});

describe('private key blocks', () => {
  it('points at the BEGIN line, spans to END, and quotes no key material', async () => {
    const findings = await scanFixtures(['s017-private-key/positive.pem']);
    expect(findings).toHaveLength(1);
    const finding = findings[0];
    expect(finding?.line).toBe(1);
    expect(finding?.endLine).toBe(5);
    expect(finding?.evidence).toBe('-----BEGIN RSA PRIVATE KEY-----');
    expect(finding?.metadata).toMatchObject({ keyType: 'RSA', terminated: true, inline: false });
  });

  it('redacts the body of a key folded onto a single line', async () => {
    const findings = await scanFixtures(['s017-private-key/inline.json']);
    expect(findings).toHaveLength(1);
    const finding = findings[0];
    expect(finding?.evidence).toContain('-----BEGIN RSA PRIVATE KEY-----');
    expect(finding?.evidence).toContain('[REDACTED]');
    expect(finding?.evidence).not.toContain('FAKEKEY');
    expect(finding?.metadata).toMatchObject({ inline: true });
  });

  it('still reports an unterminated block, without claiming an end line', async () => {
    const findings = await scanFixtures(['s017-private-key/unterminated.txt']);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.line).toBe(3);
    expect(findings[0]?.endLine).toBeUndefined();
    expect(findings[0]?.metadata).toMatchObject({ keyType: 'OPENSSH', terminated: false });
  });
});

describe('placeholder policy', () => {
  it('reports a vendor-documented example key, because the format is the evidence', async () => {
    const findings = await scanFixtures(['s001-aws-access-key-id/positive.env']);
    expect(findings.map((finding) => finding.ruleId)).toEqual(['S001']);
  });

  it('suppresses placeholder values for the name and entropy rules', async () => {
    const findings = await scanFixtures([
      's021-sensitive-assignment/negative.env',
      's022-high-entropy-assignment/negative.js',
    ]);
    expect(findings).toEqual([]);
  });
});

describe('generated-content skips', () => {
  it('ignores credential-named, high-entropy values inside a lockfile', async () => {
    const findings = await scanFixtures(['behaviour/package-lock.json']);
    expect(findings).toEqual([]);
  });

  it('ignores integrity, digest, and commit-id lines', async () => {
    const findings = await scanFixtures(['behaviour/checksums.txt']);
    expect(findings).toEqual([]);
  });
});

describe('degenerate input', () => {
  it('returns nothing for an empty file', async () => {
    await expect(scanFixtures(['behaviour/empty.env'])).resolves.toEqual([]);
  });

  it('returns nothing when handed no files at all', async () => {
    await expect(scanFixtures([])).resolves.toEqual([]);
  });

  it('skips an unreadable file instead of failing the scan', async () => {
    const { logger, messages } = recordingLogger();
    const files: FileRef[] = [
      { absPath: '/nonexistent/oversized.env', relPath: 'oversized.env', size: 10 },
      fileRef(FIXTURE_ROOT, 'behaviour/allowlist.env'),
    ];
    const context = makeContext(FIXTURE_ROOT, files, {}, logger);
    const findings = await secretsScanner.scan({
      ...context,
      readFile: async (ref) => {
        if (ref.relPath === 'oversized.env') {
          throw Object.assign(new Error('Refusing to read oversized.env: 99 bytes exceeds cap'), {
            code: 'ERR_FILE_TOO_LARGE',
          });
        }
        return context.readFile(ref);
      },
    });

    expect(findings).toHaveLength(2);
    expect(messages.some((message) => message.includes('oversized.env'))).toBe(true);
    // The read error's message must not be echoed: it can carry file content.
    expect(messages.some((message) => message.includes('Refusing to read'))).toBe(false);
  });
});

describe('cancellation', () => {
  it('throws once the signal is aborted', async () => {
    const controller = new AbortController();
    controller.abort();
    const files = [fileRef(FIXTURE_ROOT, 'behaviour/allowlist.env')];
    const context = makeContext(FIXTURE_ROOT, files, {}, undefined, controller.signal);
    await expect(secretsScanner.scan(context)).rejects.toThrow(/abort/i);
  });
});

describe('configuration', () => {
  it('suppresses a finding whose exact value is allowlisted', async () => {
    const findings = await scanFixtures(['behaviour/allowlist.env'], {
      allowlist: [GITHUB_TOKEN],
    });
    expect(findings.map((finding) => finding.ruleId)).toEqual(['S013']);
  });

  it('suppresses a whole rule when a rule id is allowlisted', async () => {
    const findings = await scanFixtures(['behaviour/allowlist.env'], { allowlist: ['S013'] });
    expect(findings.map((finding) => finding.ruleId)).toEqual(['S003']);
  });

  it('accepts values and rule ids in the same allowlist', async () => {
    const findings = await scanFixtures(['behaviour/allowlist.env'], {
      allowlist: ['S003', NPM_TOKEN],
    });
    expect(findings).toEqual([]);
  });

  it('ignores malformed allowlist entries without echoing them', async () => {
    const { logger, messages } = recordingLogger();
    const findings = await scanFixtures(
      ['behaviour/allowlist.env'],
      { allowlist: [42, null, GITHUB_TOKEN], ignorePaths: 'not-an-array' },
      logger,
    );
    expect(findings.map((finding) => finding.ruleId)).toEqual(['S013']);
    expect(messages.some((message) => message.includes('allowlist[0]'))).toBe(true);
    expect(messages.some((message) => message.includes('ignorePaths'))).toBe(true);
    expect(messages.some((message) => message.includes('42'))).toBe(false);
  });

  it('skips files matched by ignorePaths', async () => {
    const paths = ['behaviour/allowlist.env', 'ignored/vendor/keys.env'];
    const before = await scanFixtures(paths);
    expect(before.map((finding) => finding.file)).toContain('ignored/vendor/keys.env');

    const after = await scanFixtures(paths, { ignorePaths: ['ignored/**'] });
    expect(after.map((finding) => finding.file)).not.toContain('ignored/vendor/keys.env');
    expect(after).toHaveLength(2);
  });

  it('honours ignorePaths negation, last pattern wins', async () => {
    const paths = ['behaviour/allowlist.env', 'ignored/vendor/keys.env'];
    const findings = await scanFixtures(paths, {
      ignorePaths: ['ignored/**', '!ignored/vendor/**'],
    });
    expect(findings.map((finding) => finding.file)).toContain('ignored/vendor/keys.env');
  });

  it('produces nothing when the section is disabled', async () => {
    const findings = await scanFixtures(['behaviour/allowlist.env'], { enabled: false });
    expect(findings).toEqual([]);
  });

  it('works with an empty config section', async () => {
    const findings = await scanFixtures(['behaviour/allowlist.env'], {});
    expect(findings).toHaveLength(2);
  });
});

describe('determinism', () => {
  it('produces identical findings, in identical order, across runs', async () => {
    const paths = [
      's018-database-url/positive.env',
      's003-github-token/positive.yml',
      's017-private-key/positive.pem',
    ];
    const first = await scanFixtures(paths);
    const second = await scanFixtures([...paths].reverse());
    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
  });
});

describe('evidence on very long lines', () => {
  it('windows around the redaction marker instead of quoting an unrelated prefix', async () => {
    const padding = 'x'.repeat(3000);
    const line = `{"padding":"${padding}","githubToken":"${GITHUB_TOKEN}","after":"${padding}"}`;
    const files: FileRef[] = [
      { absPath: '/generated/bundle.json', relPath: 'bundle.json', size: line.length },
    ];
    const findings = await secretsScanner.scan({
      ...makeContext(FIXTURE_ROOT, files),
      readFile: async () => line,
    });

    expect(findings).toHaveLength(1);
    const evidence = findings[0]?.evidence ?? '';
    expect(evidence.length).toBeLessThanOrEqual(201);
    expect(evidence).toContain('[REDACTED]');
    expect(evidence).toContain('githubToken');
    expect(evidence.startsWith('…')).toBe(true);
    expect(evidence).not.toContain(GITHUB_TOKEN);
  });
});

describe('bounded output', () => {
  it('caps how many findings one pathological file can contribute', async () => {
    const { logger, messages } = recordingLogger();
    const generated = Array.from(
      { length: 250 },
      (_unused, index) => `TOKEN_${index}=ghp_EXAMPLEEXAMPLEEXAMPLE0000000000000000`,
    ).join('\n');
    const files: FileRef[] = [
      { absPath: '/generated/tokens.env', relPath: 'tokens.env', size: generated.length },
    ];
    const findings = await secretsScanner.scan({
      ...makeContext(FIXTURE_ROOT, files, {}, logger),
      readFile: async () => generated,
    });

    expect(findings).toHaveLength(200);
    expect(messages.some((message) => message.includes('the rest were dropped'))).toBe(true);
  });
});

describe('the leak backstop', () => {
  it('recognises a finding whose evidence still holds a raw value', () => {
    const leaking = {
      id: 'x',
      ruleId: 'S001',
      title: 'test',
      description: 'test',
      severity: 'critical' as const,
      confidence: 'high' as const,
      category: 'secrets' as const,
      file: 'a.env',
      evidence: `KEY=${GITHUB_TOKEN}`,
      recommendation: 'test',
      references: [],
      scanner: 'secrets',
    };
    expect(leaksSecret(leaking, [GITHUB_TOKEN])).toBe(true);
    expect(leaksSecret({ ...leaking, evidence: 'KEY=[REDACTED]' }, [GITHUB_TOKEN])).toBe(false);
  });

  it('also inspects metadata, not only evidence', () => {
    const leaking = {
      id: 'x',
      ruleId: 'S001',
      title: 'test',
      description: 'test',
      severity: 'critical' as const,
      confidence: 'high' as const,
      category: 'secrets' as const,
      file: 'a.env',
      evidence: 'KEY=[REDACTED]',
      recommendation: 'test',
      references: [],
      scanner: 'secrets',
      metadata: { setting: GITHUB_TOKEN },
    };
    expect(leaksSecret(leaking, [GITHUB_TOKEN])).toBe(true);
  });
});

describe('the no-leak invariant, over every fixture at once', () => {
  it('never emits a planted value in any finding field', async () => {
    const findings = await secretsScanner.scan(
      makeContext(FIXTURE_ROOT, listTextFiles(FIXTURE_ROOT)),
    );
    expect(findings.length).toBeGreaterThan(30);

    const serialized = JSON.stringify(findings);
    for (const secret of ALL_FIXTURE_SECRETS) {
      expect(serialized, `leaked ${secret.slice(0, 8)}…`).not.toContain(secret);
    }
  });

  it('never writes a planted value to the logger', async () => {
    const { logger, messages } = recordingLogger();
    await secretsScanner.scan(makeContext(FIXTURE_ROOT, listTextFiles(FIXTURE_ROOT), {}, logger));
    const logged = messages.join('\n');
    for (const secret of ALL_FIXTURE_SECRETS) {
      expect(logged, `logged ${secret.slice(0, 8)}…`).not.toContain(secret);
    }
  });
});
