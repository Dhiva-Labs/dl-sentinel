import type { RuleModule, RuleHit } from './types.js';
import { findCallSites, splitTopLevel } from '../text.js';
import { resolveArgDynamism } from '../context.js';

/**
 * C003 -- SQL built from strings.
 *
 * Flags a call to a `query`/`execute`-shaped method whose first argument is
 * built dynamically (template literal, concatenation, or one assignment hop
 * back to such an expression -- see `resolveArgDynamism`) AND whose
 * resolved text contains a SQL keyword (SELECT/INSERT/UPDATE/DELETE/WHERE)
 * near the dynamic part. This rule is intentionally language-agnostic: the
 * sink names cover common conventions across Node (pg/mysql `.query`),
 * Python DB-API (`.execute`), Ruby (`.execute`), PHP PDO (`->query` /
 * `->exec`), Go `database/sql` (`.Query` / `.Exec`), and JDBC
 * (`.executeQuery` / `.executeUpdate`).
 *
 * NOT flagged: a call whose SQL argument is a plain string literal, even if
 * it contains a placeholder (`?`, `$1`, `%s`) or SQL keywords -- with no
 * concatenation/interpolation there is nothing dynamic to inject through,
 * which is exactly the parameterized-query shape this rule must stay quiet
 * on.
 */

const SINK_NAMES = ['query', 'execute', 'Query', 'Exec', 'executeQuery', 'executeUpdate'];
const SQL_KEYWORDS = /\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE)\b/i;

export const c003SqlInjection: RuleModule = {
  meta: {
    id: 'C003',
    title: 'SQL query built from a dynamic string',
    severity: 'high',
    defaultConfidence: 'medium',
    category: 'source',
    description:
      'A query/execute call is passed SQL text built via string concatenation or ' +
      'interpolation next to SELECT/INSERT/UPDATE/DELETE/WHERE keywords, instead of a ' +
      'parameterized query. If any concatenated part is influenced by external input, ' +
      'this is a SQL injection vulnerability.',
    recommendation:
      'Use parameterized queries or prepared statements (placeholders such as `?`, ' +
      '`$1`, or `%s` with a separate params argument) instead of building SQL text by ' +
      'hand.',
    references: [],
    compliance: { cwe: ['CWE-89'], owasp: ['A03:2021'] },
  },
  languages: ['js', 'py', 'rb', 'php', 'go', 'java'],
  check(ctx) {
    const hits: RuleHit[] = [];
    for (let i = 0; i < ctx.lines.length; i++) {
      if (ctx.commentMask[i]) continue;
      const line = ctx.lines[i] ?? '';
      const lineStart = ctx.lineStarts[i] ?? 0;

      for (const site of findCallSites(line, SINK_NAMES, ctx.text, lineStart)) {
        const [firstArg] = splitTopLevel(site.args, ',');
        const result = resolveArgDynamism(ctx, firstArg ?? '', i);
        if (result.dynamic && SQL_KEYWORDS.test(result.text)) {
          hits.push({ line: i, column: site.index });
        }
      }
    }
    return hits;
  },
};
