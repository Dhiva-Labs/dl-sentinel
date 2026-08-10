import type { Finding, Severity } from '@dl-sentinel/core';
import { buildFinding } from '../build-finding.js';
import type { Locator, NormalizedApiDoc } from '../internal-types.js';
import { pointerPath } from '../pointer.js';
import { isLocalHost, parseUrlish } from '../util.js';

/** A003 — non-HTTPS server URL / scheme (OpenAPI 3 servers[], Swagger 2 schemes[]). */
export function runNonHttpsServers(
  doc: NormalizedApiDoc,
  file: string,
  locator: Locator,
): Finding[] {
  const findings: Finding[] = [];
  for (const server of doc.servers) {
    const parsed = parseUrlish(server.url);
    if (!parsed || parsed.scheme !== 'http') continue;
    const local = isLocalHost(parsed.hostname);
    const severity: Severity = local ? 'info' : 'medium';
    const loc = locator.locate(server.path);
    findings.push(
      buildFinding({
        ruleId: 'A003',
        title: 'Non-HTTPS server URL',
        description: `The document declares a server using the plain http:// scheme${
          local
            ? ' (a localhost/loopback address — likely a local dev server, lower real-world risk)'
            : ''
        }. Plain HTTP transmits requests, responses, and any credentials unencrypted.`,
        severity,
        confidence: 'high',
        qualifier: 'confirmed',
        file,
        line: loc.line,
        column: loc.column,
        evidence: `${pointerPath(server.path)} = ${server.url}`,
        recommendation:
          'Serve the API only over https:// and remove or deprecate plain-http server entries.',
      }),
    );
  }
  return findings;
}
