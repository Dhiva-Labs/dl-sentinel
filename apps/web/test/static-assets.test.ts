import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const publicDir = fileURLToPath(new URL('../public', import.meta.url));

const indexHtml = readFileSync(join(publicDir, 'index.html'), 'utf8');
const appJs = readFileSync(join(publicDir, 'app.js'), 'utf8');
const stylesCss = readFileSync(join(publicDir, 'styles.css'), 'utf8');

// No http(s):// anywhere — the dashboard must be fully self-contained and
// offline-capable: no CDN scripts/styles/fonts, no remote images, no
// external API defaults baked in.
const EXTERNAL_URL_PATTERN = /https?:\/\//i;

describe('public/index.html', () => {
  it('exists and is non-empty', () => {
    expect(indexHtml.length).toBeGreaterThan(0);
  });

  it('references app.js', () => {
    expect(indexHtml).toMatch(/<script[^>]+src=["']\.?\/?app\.js["']/);
  });

  it('references styles.css', () => {
    expect(indexHtml).toMatch(/<link[^>]+href=["']\.?\/?styles\.css["']/);
  });

  it('contains no external http(s) resource URLs', () => {
    expect(indexHtml).not.toMatch(EXTERNAL_URL_PATTERN);
  });

  it('is a real HTML document', () => {
    expect(indexHtml.toLowerCase()).toContain('<!doctype html>');
    expect(indexHtml).toContain('<html');
    expect(indexHtml).toContain('</html>');
  });
});

describe('public/app.js', () => {
  it('exists and is non-empty', () => {
    expect(appJs.length).toBeGreaterThan(0);
  });

  it('contains no external http(s) resource URLs', () => {
    expect(appJs).not.toMatch(EXTERNAL_URL_PATTERN);
  });

  it('never uses innerHTML (DOM built via textContent/createElement instead)', () => {
    expect(appJs).not.toMatch(/\.innerHTML\s*=/);
  });
});

describe('public/styles.css', () => {
  it('exists and is non-empty', () => {
    expect(stylesCss.length).toBeGreaterThan(0);
  });

  it('contains no external http(s) resource URLs (e.g. no remote @import/font/CDN)', () => {
    expect(stylesCss).not.toMatch(EXTERNAL_URL_PATTERN);
  });
});
