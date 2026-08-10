import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import type { ScanContext, ScanLogger } from '@dl-sentinel/core';
import { infraScanner } from '../src/index.js';
import { fileRef, fixturePath, scanFixture, scanFixtures } from './helpers.js';

interface RecordingLogger extends ScanLogger {
  warnings: string[];
}

function recordingLogger(): RecordingLogger {
  const warnings: string[] = [];
  return {
    warnings,
    debug: () => {},
    info: () => {},
    warn: (message: string) => warnings.push(message),
    error: () => {},
  };
}

function contextFor(relPath: string, logger: ScanLogger): ScanContext {
  return {
    rootDir: fixturePath(),
    files: [fileRef(relPath)],
    config: {},
    signal: new AbortController().signal,
    logger,
    readFile: (ref) => Promise.resolve(readFileSync(ref.absPath, 'utf8')),
  };
}

describe('malformed input handling', () => {
  it('warns and skips an unparseable YAML file without throwing', async () => {
    const logger = recordingLogger();
    const findings = await infraScanner.scan(contextFor('malformed/invalid.yaml', logger));
    expect(findings).toHaveLength(0);
    expect(logger.warnings.some((m) => m.includes('malformed/invalid.yaml'))).toBe(true);
  });

  it('does not crash on a Dockerfile truncated mid-continuation', async () => {
    const findings = await scanFixture('malformed/truncated-dockerfile/Dockerfile');
    expect(Array.isArray(findings)).toBe(true);
  });

  it('does not crash on an empty YAML file, and warns', async () => {
    const logger = recordingLogger();
    const findings = await infraScanner.scan(contextFor('malformed/empty.yml', logger));
    expect(findings).toHaveLength(0);
    expect(logger.warnings.length).toBeGreaterThan(0);
  });

  it('does not crash on an empty Dockerfile', async () => {
    const findings = await scanFixture('malformed/empty-dockerfile/Dockerfile');
    expect(findings).toHaveLength(0);
  });

  it('does not crash on malformed (brace-unbalanced) Terraform', async () => {
    const findings = await scanFixture('terraform/malformed/main.tf');
    expect(Array.isArray(findings)).toBe(true);
  });

  it('isolates a malformed file from the rest of the scan: other files still produce findings', async () => {
    const findings = await scanFixtures([
      'malformed/invalid.yaml',
      'malformed/truncated-dockerfile/Dockerfile',
      'terraform/malformed/main.tf',
      'compose/privileged/docker-compose.yml',
    ]);
    const i010 = findings.filter((f) => f.ruleId === 'I010');
    expect(i010).toHaveLength(1);
    expect(i010[0]?.file).toBe('compose/privileged/docker-compose.yml');
  });
});
