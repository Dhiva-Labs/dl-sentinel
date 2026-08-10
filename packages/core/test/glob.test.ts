import { describe, expect, it } from 'vitest';
import { createMatcher, globToRegExp, matchAny, matchGlob, normalizePath } from '../src/glob.js';

describe('normalizePath', () => {
  it('strips leading ./ and /, converts backslashes', () => {
    expect(normalizePath('./src/app.ts')).toBe('src/app.ts');
    expect(normalizePath('/src/app.ts')).toBe('src/app.ts');
    expect(normalizePath('src\\app.ts')).toBe('src/app.ts');
  });
});

describe('matchGlob', () => {
  it('matches ** at any depth including zero segments', () => {
    expect(matchGlob('a.ts', '**/*.ts')).toBe(true);
    expect(matchGlob('src/a.ts', '**/*.ts')).toBe(true);
    expect(matchGlob('src/deep/nested/a.ts', '**/*.ts')).toBe(true);
    expect(matchGlob('a.tsx', '**/*.ts')).toBe(false);
  });

  it('anchors patterns to the full path', () => {
    expect(matchGlob('README.md', '*.md')).toBe(true);
    expect(matchGlob('docs/guide.md', '*.md')).toBe(false);
  });

  it('* stays within a segment', () => {
    expect(matchGlob('src/app.ts', 'src/*.ts')).toBe(true);
    expect(matchGlob('src/sub/app.ts', 'src/*.ts')).toBe(false);
  });

  it('? matches exactly one non-slash character', () => {
    expect(matchGlob('a1.ts', 'a?.ts')).toBe(true);
    expect(matchGlob('a12.ts', 'a?.ts')).toBe(false);
    expect(matchGlob('a/.ts', 'a?.ts')).toBe(false);
  });

  it('matches directory subtrees', () => {
    expect(matchGlob('node_modules/x/y.js', '**/node_modules/**')).toBe(true);
    expect(matchGlob('a/node_modules/b.js', '**/node_modules/**')).toBe(true);
    expect(matchGlob('node_modules_x/y.js', '**/node_modules/**')).toBe(false);
  });

  it('expands braces', () => {
    expect(matchGlob('src/a.ts', 'src/**/*.{ts,tsx}')).toBe(true);
    expect(matchGlob('src/a.tsx', 'src/**/*.{ts,tsx}')).toBe(true);
    expect(matchGlob('src/a.js', 'src/**/*.{ts,tsx}')).toBe(false);
  });

  it('treats a trailing slash as the whole directory', () => {
    expect(matchGlob('dist/a.js', 'dist/')).toBe(true);
    expect(matchGlob('dist/sub/a.js', 'dist/')).toBe(true);
    expect(matchGlob('distx/a.js', 'dist/')).toBe(false);
  });

  it('matches dotfiles (no special-casing)', () => {
    expect(matchGlob('.env', '**/*.env')).toBe(true); // '*' may match empty — .env is caught
    expect(matchGlob('.env', '**/.env')).toBe(true);
    expect(matchGlob('config/.env', '**/.env')).toBe(true);
    expect(matchGlob('.env', '.*')).toBe(true);
  });

  it('escapes regex metacharacters in literals', () => {
    expect(matchGlob('a+b.txt', 'a+b.txt')).toBe(true);
    expect(matchGlob('aab.txt', 'a+b.txt')).toBe(false);
    expect(matchGlob('a.b', 'a.b')).toBe(true);
    expect(matchGlob('axb', 'a.b')).toBe(false);
  });
});

describe('globToRegExp', () => {
  it('produces an anchored regex', () => {
    const re = globToRegExp('src/*.ts');
    expect(re.test('src/a.ts')).toBe(true);
    expect(re.test('xsrc/a.ts')).toBe(false);
    expect(re.test('src/a.ts.bak')).toBe(false);
  });
});

describe('createMatcher (gitignore-style, last match wins)', () => {
  it('applies negation after inclusion', () => {
    const matcher = createMatcher(['config/**', '!config/public/**']);
    expect(matcher('config/app.yml')).toBe(true);
    expect(matcher('config/public/logo.svg')).toBe(false);
  });

  it('re-includes after negation when a later pattern matches', () => {
    const matcher = createMatcher(['**/*.env', '!test/**', 'test/real.env']);
    expect(matcher('prod/app.env')).toBe(true);
    expect(matcher('test/sample.env')).toBe(false);
    expect(matcher('test/real.env')).toBe(true);
  });

  it('excludes when nothing matches', () => {
    const matcher = createMatcher(['src/**']);
    expect(matcher('docs/readme.md')).toBe(false);
  });

  it('matchAny is a one-shot matcher', () => {
    expect(matchAny('a/b/c.py', ['**/*.py'])).toBe(true);
    expect(matchAny('a/b/c.py', ['**/*.js'])).toBe(false);
  });
});
