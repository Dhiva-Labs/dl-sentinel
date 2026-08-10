import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Finding, ScanContext, ScanLogger, ScannerPlugin } from '@dl-sentinel/core';
import { createFinding } from '@dl-sentinel/core';

/** Absolute path of the committed discovery fixture tree. */
export const FIXTURE_TREE = fileURLToPath(new URL('./fixtures/tree', import.meta.url));

export interface RecordingLogger extends ScanLogger {
  messages: { level: 'debug' | 'info' | 'warn' | 'error'; message: string }[];
  of(level: 'debug' | 'info' | 'warn' | 'error'): string[];
}

/** Logger that keeps everything it was told, for assertions on warnings. */
export function recordingLogger(): RecordingLogger {
  const messages: RecordingLogger['messages'] = [];
  return {
    messages,
    of(level) {
      return messages.filter((entry) => entry.level === level).map((entry) => entry.message);
    },
    debug: (message) => messages.push({ level: 'debug', message }),
    info: (message) => messages.push({ level: 'info', message }),
    warn: (message) => messages.push({ level: 'warn', message }),
    error: (message) => messages.push({ level: 'error', message }),
  };
}

export interface MockPluginOptions {
  id: string;
  supportedFiles?: string[];
  scan?: (context: ScanContext) => Promise<Finding[]>;
}

/** Minimal ScannerPlugin whose behavior the test supplies. */
export function mockPlugin(options: MockPluginOptions): ScannerPlugin {
  return {
    id: options.id,
    name: `${options.id} scanner`,
    version: '0.0.0-test',
    categories: ['other'],
    supportedFiles: options.supportedFiles ?? [],
    rules: [],
    scan: options.scan ?? (async () => []),
  };
}

/** A plugin that returns the given findings, re-attributed to itself. */
export function pluginReturning(id: string, findings: Omit<Finding, 'id' | 'scanner'>[]) {
  return mockPlugin({
    id,
    scan: async () => findings.map((input) => createFinding({ ...input, scanner: id })),
  });
}

/** A plugin that always throws. */
export function failingPlugin(id: string, message = `${id} exploded`): ScannerPlugin {
  return mockPlugin({
    id,
    scan: async () => {
      throw new Error(message);
    },
  });
}

/** Build a Finding, overriding whichever fields the test cares about. */
export function testFinding(overrides: Partial<Omit<Finding, 'id'>> = {}): Finding {
  return createFinding({
    ruleId: 'C001',
    title: 'Example finding',
    description: 'Produced by a mock scanner.',
    severity: 'medium',
    confidence: 'medium',
    category: 'other',
    file: 'src/app.ts',
    line: 1,
    column: 1,
    evidence: 'const example = [REDACTED];',
    recommendation: 'Nothing to do; this is a fixture.',
    references: [],
    scanner: 'mock',
    ...overrides,
  });
}

/** Fields of a Finding without the engine-managed id/scanner. */
export function findingInput(
  overrides: Partial<Omit<Finding, 'id' | 'scanner'>> = {},
): Omit<Finding, 'id' | 'scanner'> {
  const { id: _id, scanner: _scanner, ...rest } = testFinding();
  return { ...rest, ...overrides };
}

/** Create a temp directory and a disposer that removes it. */
export async function makeTempDir(): Promise<{ dir: string; cleanup: () => Promise<void> }> {
  const dir = await mkdtemp(path.join(tmpdir(), 'dl-sentinel-engine-'));
  return {
    dir,
    cleanup: async () => {
      await rm(dir, { recursive: true, force: true });
    },
  };
}
