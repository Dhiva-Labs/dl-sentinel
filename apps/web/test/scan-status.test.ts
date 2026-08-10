import { describe, expect, it } from 'vitest';
import { isTerminalStatus, scanStatusClass, scanStatusLabel } from '../src/scan-status.js';

describe('scanStatusLabel', () => {
  it('capitalizes a known status', () => {
    expect(scanStatusLabel('queued')).toBe('Queued');
    expect(scanStatusLabel('running')).toBe('Running');
    expect(scanStatusLabel('completed')).toBe('Completed');
    expect(scanStatusLabel('failed')).toBe('Failed');
  });

  it('falls back to "Unknown" for anything else', () => {
    expect(scanStatusLabel('weird')).toBe('Unknown');
    expect(scanStatusLabel('')).toBe('Unknown');
  });
});

describe('scanStatusClass', () => {
  it('prefixes a known status with "status-"', () => {
    expect(scanStatusClass('queued')).toBe('status-queued');
    expect(scanStatusClass('completed')).toBe('status-completed');
  });

  it('maps an unknown status to "status-unknown"', () => {
    expect(scanStatusClass('nope')).toBe('status-unknown');
  });
});

describe('isTerminalStatus', () => {
  it('is true only for completed and failed', () => {
    expect(isTerminalStatus('completed')).toBe(true);
    expect(isTerminalStatus('failed')).toBe(true);
    expect(isTerminalStatus('queued')).toBe(false);
    expect(isTerminalStatus('running')).toBe(false);
  });
});
