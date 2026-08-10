import { describe, expect, it } from 'vitest';
import { escapeHtml } from '../src/html.js';
import { formatInterval } from '../src/schedule.js';

describe('formatInterval', () => {
  it('formats whole minutes and hours', () => {
    expect(formatInterval(60_000)).toBe('1m');
    expect(formatInterval(5 * 60_000)).toBe('5m');
    expect(formatInterval(3_600_000)).toBe('1h');
  });

  it('combines hours, minutes and seconds', () => {
    expect(formatInterval(5_400_000)).toBe('1h 30m');
    expect(formatInterval(90_000)).toBe('1m 30s');
  });

  it('returns a dash for invalid input', () => {
    expect(formatInterval(Number.NaN)).toBe('—');
    expect(formatInterval(-1)).toBe('—');
  });
});

// The dashboard builds every DOM node from API data via textContent /
// createElement (never innerHTML — enforced by static-assets.test.ts), so
// schedule/scan fields are inert wherever they render. escapeHtml is the
// belt-and-braces path for the rare spot that assembles a plain string; verify
// it neutralizes hostile values that could arrive in a schedule path or scan id.
describe('escapeHtml on schedule/scan fields', () => {
  it('neutralizes a malicious schedule path', () => {
    const evil = '/repo/<img src=x onerror=alert(1)>';
    const escaped = escapeHtml(evil);
    expect(escaped).not.toContain('<img');
    expect(escaped).toContain('&lt;img');
  });

  it('neutralizes a malicious scan id / project name', () => {
    expect(escapeHtml('"><script>alert(1)</script>')).toBe(
      '&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;',
    );
  });
});
