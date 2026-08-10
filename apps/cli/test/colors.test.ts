import { describe, expect, it } from 'vitest';
import { makeColors, shouldColor } from '../src/colors.js';

const ESC = String.fromCharCode(27);

describe('shouldColor', () => {
  it('is enabled on a TTY with a clean environment and no --no-color', () => {
    expect(shouldColor({ noColorFlag: false, env: {}, isTTY: true })).toBe(true);
  });

  it('is disabled when stdout is not a TTY', () => {
    expect(shouldColor({ noColorFlag: false, env: {}, isTTY: false })).toBe(false);
  });

  it('is disabled by the --no-color flag even on a TTY', () => {
    expect(shouldColor({ noColorFlag: true, env: {}, isTTY: true })).toBe(false);
  });

  it('is disabled when NO_COLOR is set to a non-empty value', () => {
    expect(shouldColor({ noColorFlag: false, env: { NO_COLOR: '1' }, isTTY: true })).toBe(false);
  });

  it('ignores an empty NO_COLOR value', () => {
    expect(shouldColor({ noColorFlag: false, env: { NO_COLOR: '' }, isTTY: true })).toBe(true);
  });
});

describe('makeColors', () => {
  it('wraps text in ANSI escapes when enabled', () => {
    const colors = makeColors(true);
    expect(colors.red('x')).toBe(`${ESC}[31mx${ESC}[39m`);
    expect(colors.bold('x')).toBe(`${ESC}[1mx${ESC}[22m`);
  });

  it('is the identity when disabled (no escape bytes)', () => {
    const colors = makeColors(false);
    expect(colors.red('x')).toBe('x');
    expect(colors.bold(colors.cyan('x'))).toBe('x');
    expect(colors.green('x').includes(ESC)).toBe(false);
  });

  it('keeps the visible width when padding is wrapped', () => {
    const colors = makeColors(true);
    // Padding first, then color: the escapes are zero-width so alignment holds.
    const painted = colors.yellow('hi'.padEnd(6));
    expect(painted.replace(new RegExp(`${ESC}\\[[0-9]+m`, 'g'), '')).toBe('hi    ');
  });
});
