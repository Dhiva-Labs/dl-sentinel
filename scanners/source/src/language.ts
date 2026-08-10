/**
 * Language classification for the source scanner. We deliberately use a
 * coarse set of "language families" rather than one tag per extension:
 * JS, JSX, TS, TSX, MJS, and CJS all share the same lexical rules (template
 * literals, line and block comments, `+` concatenation) so a single `js`
 * family keeps every rule's per-language logic simple.
 */

export type Lang = 'js' | 'py' | 'rb' | 'php' | 'go' | 'java' | 'other';

const EXTENSION_TO_LANG: Readonly<Record<string, Lang>> = {
  js: 'js',
  jsx: 'js',
  ts: 'js',
  tsx: 'js',
  mjs: 'js',
  cjs: 'js',
  py: 'py',
  rb: 'rb',
  php: 'php',
  go: 'go',
  java: 'java',
};

/** Classify a repo-relative (or absolute) path by its extension. */
export function detectLanguage(relPath: string): Lang {
  const match = /\.([A-Za-z0-9]+)$/.exec(relPath);
  const ext = match?.[1]?.toLowerCase();
  if (!ext) return 'other';
  return EXTENSION_TO_LANG[ext] ?? 'other';
}

/** Line-comment marker(s) for a language family. */
export function lineCommentMarkers(lang: Lang): readonly string[] {
  switch (lang) {
    case 'js':
    case 'go':
    case 'java':
    case 'php':
      return ['//'];
    case 'py':
    case 'rb':
      return ['#'];
    default:
      return ['//', '#'];
  }
}

/** Whether a language family uses C-style slash-star block comments. */
export function usesSlashStarBlocks(lang: Lang): boolean {
  return lang === 'js' || lang === 'go' || lang === 'java' || lang === 'php';
}

/** Whether a language family uses Python-style triple-quoted docstrings. */
export function usesTripleQuoteDocstrings(lang: Lang): boolean {
  return lang === 'py';
}
