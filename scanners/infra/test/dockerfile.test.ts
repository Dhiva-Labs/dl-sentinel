import { describe, expect, it } from 'vitest';
import { parseDockerfile, parseInstructions } from '../src/dockerfile/parse.js';
import { byRule, lastLineOf, lineOf, readFixture, scanFixture } from './helpers.js';

describe('Dockerfile parser', () => {
  it('joins backslash-continued lines into one logical instruction', () => {
    const text = ['RUN echo one \\', '    && echo two \\', '    && echo three'].join('\n');
    const instructions = parseInstructions(text);
    expect(instructions).toHaveLength(1);
    expect(instructions[0]?.instruction).toBe('RUN');
    expect(instructions[0]?.args).toBe('echo one && echo two && echo three');
    expect(instructions[0]?.line).toBe(1);
  });

  it('skips a comment-only line inside a continuation without breaking it', () => {
    const text = [
      'RUN echo one \\',
      '# a full comment line, mid-continuation',
      '    && echo two',
    ].join('\n');
    const instructions = parseInstructions(text);
    expect(instructions).toHaveLength(1);
    expect(instructions[0]?.args).toBe('echo one && echo two');
  });

  it('does not treat a line ending in an even number of backslashes as a continuation', () => {
    // Two trailing backslashes is one *escaped* backslash, not a line-continuation marker.
    const text = ['RUN echo hello\\\\', 'USER node'].join('\n');
    const instructions = parseInstructions(text);
    expect(instructions.map((i) => i.instruction)).toEqual(['RUN', 'USER']);
  });

  it('upper-cases instruction keywords regardless of source casing', () => {
    const instructions = parseInstructions('from node:20\nuser node\n');
    expect(instructions.map((i) => i.instruction)).toEqual(['FROM', 'USER']);
  });

  it('ignores blank lines and whole-line comments', () => {
    const instructions = parseInstructions('# leading comment\n\nFROM node:20\n\n# trailing\n');
    expect(instructions).toHaveLength(1);
  });

  it('resolves multi-stage FROM, stage names, and alias references', () => {
    const text = [
      'FROM node:20 AS build',
      'RUN echo hi',
      'FROM build AS test',
      'RUN echo bye',
      'FROM node:20-slim',
    ].join('\n');
    const parsed = parseDockerfile(text);
    expect(parsed.stages).toHaveLength(3);
    expect(parsed.stages[0]).toMatchObject({ name: 'build', image: 'node:20', isAlias: false });
    expect(parsed.stages[1]).toMatchObject({ name: 'test', image: 'build', isAlias: true });
    expect(parsed.stages[2]).toMatchObject({ image: 'node:20-slim', isAlias: false });
  });

  it('strips a --platform flag from FROM before extracting the image', () => {
    const parsed = parseDockerfile('FROM --platform=linux/amd64 node:20 AS build\n');
    expect(parsed.stages[0]?.image).toBe('node:20');
    expect(parsed.stages[0]?.name).toBe('build');
  });

  it('tracks the last USER instruction per stage', () => {
    const parsed = parseDockerfile('FROM node:20\nUSER node\nUSER root\n');
    expect(parsed.stages[0]?.lastUser).toMatchObject({ value: 'root', line: 3 });
  });
});

describe('I001 container runs as root', () => {
  it('flags a Dockerfile with no USER instruction at all', async () => {
    const findings = await scanFixture('dockerfile/root-implicit/Dockerfile');
    const text = readFixture('dockerfile/root-implicit/Dockerfile');
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      ruleId: 'I001',
      severity: 'high',
      confidence: 'high',
      category: 'docker',
      file: 'dockerfile/root-implicit/Dockerfile',
      line: lineOf(text, 'FROM node'),
    });
  });

  it('flags a Dockerfile whose last USER switches back to root', async () => {
    const findings = await scanFixture('dockerfile/root-explicit/Dockerfile');
    const text = readFixture('dockerfile/root-explicit/Dockerfile');
    const i001 = byRule(findings, 'I001');
    expect(i001).toHaveLength(1);
    expect(i001[0]).toMatchObject({ line: lineOf(text, 'USER root'), evidence: 'USER root' });
  });

  it('does not flag a non-root final USER', async () => {
    const findings = await scanFixture('dockerfile/non-root/Dockerfile');
    expect(findings).toHaveLength(0);
  });

  it('evaluates root-ness against the final stage, not an earlier stage', async () => {
    const findings = await scanFixture('dockerfile/multistage-final-root/Dockerfile');
    const text = readFixture('dockerfile/multistage-final-root/Dockerfile');
    expect(findings).toHaveLength(1);
    // The final stage's FROM is the *last* occurrence of "FROM node" in the file;
    // that stage never sets USER, even though the builder stage did.
    expect(findings[0]).toMatchObject({ ruleId: 'I001', line: lastLineOf(text, 'FROM node') });
  });
});

describe('I002 ADD with remote URL', () => {
  it('flags ADD from an http(s) URL', async () => {
    const findings = await scanFixture('dockerfile/add-remote-url/Dockerfile');
    expect(byRule(findings, 'I002')).toHaveLength(1);
    expect(byRule(findings, 'I002')[0]).toMatchObject({ severity: 'medium', confidence: 'high' });
  });

  it('does not flag ADD of a local archive', async () => {
    const findings = await scanFixture('dockerfile/add-local/Dockerfile');
    expect(findings).toHaveLength(0);
  });
});

describe('I003 unpinned base image', () => {
  it('flags an explicit :latest tag', async () => {
    const findings = await scanFixture('dockerfile/unpinned-latest/Dockerfile');
    expect(byRule(findings, 'I003')).toHaveLength(1);
  });

  it('flags a missing tag, without mistaking a registry port for one', async () => {
    const findings = await scanFixture('dockerfile/unpinned-no-tag/Dockerfile');
    const i003 = byRule(findings, 'I003');
    expect(i003).toHaveLength(1);
    expect(i003[0]?.evidence).toContain('registry.example.com:5000/node');
  });

  it('does not flag a digest-pinned image', async () => {
    const findings = await scanFixture('dockerfile/pinned-digest/Dockerfile');
    expect(findings).toHaveLength(0);
  });

  it('does not flag a FROM that references an earlier stage alias', async () => {
    const findings = await scanFixture('dockerfile/stage-alias/Dockerfile');
    expect(findings).toHaveLength(0);
  });

  it('never flags `scratch`', async () => {
    const findings = await scanFixture('dockerfile/scratch-base/Dockerfile');
    expect(findings).toHaveLength(0);
  });
});

describe('I004 secret in ENV/ARG', () => {
  it('flags a literal credential-shaped ENV value and redacts it', async () => {
    const findings = await scanFixture('dockerfile/secret-env/Dockerfile');
    const i004 = byRule(findings, 'I004');
    expect(i004).toHaveLength(1);
    expect(i004[0]).toMatchObject({ severity: 'critical', confidence: 'medium' });
    expect(i004[0]?.evidence).not.toContain('FAKEPASSWORDEXAMPLE123');
    expect(i004[0]?.evidence).toContain('[REDACTED]');
    expect(JSON.stringify(i004)).not.toContain('FAKEPASSWORDEXAMPLE123');
  });

  it('does not flag placeholders, references, ARG without a default, or non-secret names', async () => {
    const findings = await scanFixture('dockerfile/placeholder-env/Dockerfile');
    expect(byRule(findings, 'I004')).toHaveLength(0);
  });
});

describe('I005 piped remote script execution', () => {
  it('flags curl | bash', async () => {
    const findings = await scanFixture('dockerfile/piped-install/Dockerfile');
    expect(byRule(findings, 'I005')).toHaveLength(1);
  });

  it('does not flag a download-then-verify-then-run RUN instruction', async () => {
    const findings = await scanFixture('dockerfile/safe-install/Dockerfile');
    expect(findings).toHaveLength(0);
  });
});

describe('I006 administrative port exposed', () => {
  it('flags EXPOSE of an admin port among others', async () => {
    const findings = await scanFixture('dockerfile/admin-port/Dockerfile');
    const i006 = byRule(findings, 'I006');
    expect(i006).toHaveLength(1);
    expect(i006[0]).toMatchObject({ severity: 'low', confidence: 'medium' });
  });

  it('does not flag an ordinary application port', async () => {
    const findings = await scanFixture('dockerfile/normal-port/Dockerfile');
    expect(findings).toHaveLength(0);
  });
});
