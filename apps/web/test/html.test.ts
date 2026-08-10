import { describe, expect, it } from 'vitest';
import { escapeHtml } from '../src/html.js';

describe('escapeHtml', () => {
  it('escapes the five HTML-significant characters', () => {
    expect(escapeHtml('&<>"\'')).toBe('&amp;&lt;&gt;&quot;&#39;');
  });

  it('leaves ordinary text unchanged', () => {
    expect(escapeHtml('Hardcoded credential detected')).toBe('Hardcoded credential detected');
  });

  it('neutralizes a script-tag XSS attempt', () => {
    const out = escapeHtml('<script>alert(1)</script>');
    expect(out).not.toContain('<script>');
    expect(out).toBe('&lt;script&gt;alert(1)&lt;/script&gt;');
  });

  it('neutralizes an attribute-breakout attempt', () => {
    const out = escapeHtml('" onmouseover="alert(1)');
    expect(out).not.toContain('"');
    expect(out).toContain('&quot;');
  });

  it('is a no-op on an already-redacted evidence string', () => {
    expect(escapeHtml('API_KEY=[REDACTED]')).toBe('API_KEY=[REDACTED]');
  });
});
