import { describe, expect, it } from 'vitest';
import { EXIT } from '../src/exit-codes.js';
import { runCli } from './helpers.js';

describe('top-level dispatch', () => {
  it('prints usage to stderr and exits 64 when given no command', async () => {
    const { code, stdout, stderr } = await runCli([]);
    expect(code).toBe(EXIT.USAGE);
    expect(stdout).toBe('');
    expect(stderr).toContain('Usage: sentinel <command>');
  });

  it('prints help to stdout and exits 0 for --help', async () => {
    const { code, stdout } = await runCli(['--help']);
    expect(code).toBe(EXIT.OK);
    expect(stdout).toContain('Usage: sentinel <command>');
  });

  it('accepts -h as help', async () => {
    const { code, stdout } = await runCli(['-h']);
    expect(code).toBe(EXIT.OK);
    expect(stdout).toContain('Commands:');
  });

  it('prints the version for --version and exits 0', async () => {
    const { code, stdout } = await runCli(['--version']);
    expect(code).toBe(EXIT.OK);
    expect(stdout.trim()).toBe('DL Sentinel 0.1.0');
  });

  it('exits 64 on an unknown command', async () => {
    const { code, stderr } = await runCli(['frobnicate']);
    expect(code).toBe(EXIT.USAGE);
    expect(stderr).toContain('Unknown command: frobnicate');
  });

  it('routes to a command help without running it', async () => {
    const { code, stdout } = await runCli(['scan', '--help']);
    expect(code).toBe(EXIT.OK);
    expect(stdout).toContain('Usage: sentinel scan');
  });
});

describe('version command', () => {
  it('prints tool name and version', async () => {
    const { code, stdout } = await runCli(['version']);
    expect(code).toBe(EXIT.OK);
    expect(stdout.trim()).toBe('DL Sentinel 0.1.0');
  });

  it('supports --format json', async () => {
    const { code, stdout } = await runCli(['version', '--format', 'json']);
    expect(code).toBe(EXIT.OK);
    expect(JSON.parse(stdout)).toEqual({ name: 'DL Sentinel', version: '0.1.0' });
  });

  it('rejects an unknown flag with exit 64', async () => {
    const { code } = await runCli(['version', '--wat']);
    expect(code).toBe(EXIT.USAGE);
  });
});
