import { describe, expect, it } from 'vitest';
import { parseBool, parseInputs, parseSeverityList, resolveToken } from '../src/inputs.js';

describe('parseInputs', () => {
  it('applies the documented defaults on an empty environment', () => {
    const inputs = parseInputs({});
    expect(inputs.path).toBe('.');
    expect(inputs.failOn).toEqual(['critical', 'high']);
    expect(inputs.comment).toBe(true);
    expect(inputs.sarif).toBe(true);
    expect(inputs.sarifFile).toBe('sentinel-results.sarif');
    expect(inputs.scanners).toBeUndefined();
    expect(inputs.baselineFile).toBeUndefined();
    expect(inputs.basePath).toBeUndefined();
    expect(inputs.config).toBeUndefined();
  });

  it('reads every override from INPUT_* variables', () => {
    const inputs = parseInputs({
      INPUT_PATH: 'src',
      INPUT_FAIL_ON: 'critical',
      INPUT_SCANNERS: 'secrets, dependencies ,',
      INPUT_BASELINE: '.sentinel-baseline.json',
      INPUT_BASE_PATH: '.sentinel-base',
      INPUT_CONFIG: 'ci/sentinel.yml',
      INPUT_COMMENT: 'false',
      INPUT_SARIF: 'false',
      INPUT_SARIF_FILE: 'out/results.sarif',
    });
    expect(inputs.path).toBe('src');
    expect(inputs.failOn).toEqual(['critical']);
    expect(inputs.scanners).toEqual(['secrets', 'dependencies']);
    expect(inputs.baselineFile).toBe('.sentinel-baseline.json');
    expect(inputs.basePath).toBe('.sentinel-base');
    expect(inputs.config).toBe('ci/sentinel.yml');
    expect(inputs.comment).toBe(false);
    expect(inputs.sarif).toBe(false);
    expect(inputs.sarifFile).toBe('out/results.sarif');
  });

  it('treats blank values as absent (falls back to defaults)', () => {
    const inputs = parseInputs({
      INPUT_PATH: '   ',
      INPUT_SCANNERS: '  ',
      INPUT_FAIL_ON: '',
      INPUT_SARIF_FILE: '',
    });
    expect(inputs.path).toBe('.');
    expect(inputs.scanners).toBeUndefined();
    expect(inputs.failOn).toEqual(['critical', 'high']);
    expect(inputs.sarifFile).toBe('sentinel-results.sarif');
  });

  it('throws on an unknown fail_on severity', () => {
    expect(() => parseInputs({ INPUT_FAIL_ON: 'critical,nope' })).toThrow(/nope/);
  });
});

describe('parseBool', () => {
  it('recognizes truthy and falsy spellings, case-insensitively', () => {
    for (const v of ['true', 'TRUE', '1', 'yes', 'Yes']) expect(parseBool(v, false)).toBe(true);
    for (const v of ['false', 'FALSE', '0', 'no']) expect(parseBool(v, true)).toBe(false);
  });
  it('falls back to the default for blank/unknown values', () => {
    expect(parseBool(undefined, true)).toBe(true);
    expect(parseBool('', true)).toBe(true);
    expect(parseBool('maybe', false)).toBe(false);
  });
});

describe('parseSeverityList', () => {
  it('parses and validates a list, using the fallback when absent', () => {
    expect(parseSeverityList('critical,high', ['low'])).toEqual(['critical', 'high']);
    expect(parseSeverityList(undefined, ['critical', 'high'])).toEqual(['critical', 'high']);
  });
  it('throws on an unknown severity', () => {
    expect(() => parseSeverityList('high,bogus', ['high'])).toThrow(/bogus/);
  });
});

describe('resolveToken', () => {
  it('prefers INPUT_TOKEN, then GITHUB_TOKEN, else undefined', () => {
    expect(resolveToken({ INPUT_TOKEN: 'a', GITHUB_TOKEN: 'b' })).toBe('a');
    expect(resolveToken({ GITHUB_TOKEN: 'b' })).toBe('b');
    expect(resolveToken({ INPUT_TOKEN: '   ' })).toBeUndefined();
    expect(resolveToken({})).toBeUndefined();
  });
});
