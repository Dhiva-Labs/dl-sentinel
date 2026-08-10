import { redactEvidence } from '@dl-sentinel/core';
import type { Finding } from '@dl-sentinel/core';
import { buildFinding } from '../build-finding.js';
import {
  authParamValue,
  requestUrlHost,
  requestUrlProtocol,
  requestUrlString,
  type PostmanDoc,
} from '../postman.js';
import { pointerPath } from '../pointer.js';
import {
  classifyStandaloneValue,
  findTokenInText,
  hasTemplateReference,
  keyLooksSecret,
  looksLikePlaceholder,
} from '../secret-heuristics.js';
import { isLocalHost, isPlainObject, parseUrlish } from '../util.js';

/** A002 (Postman) — auth type apikey sent via the query string. */
export function runApiKeyInQueryPostman(doc: PostmanDoc, file: string): Finding[] {
  const findings: Finding[] = [];
  for (const site of doc.authSites) {
    if (site.auth.type !== 'apikey') continue;
    const inValue = authParamValue(site.auth, 'apikey', 'in');
    if (inValue !== 'query') continue;
    findings.push(
      buildFinding({
        ruleId: 'A002',
        title: 'API key transmitted via query string',
        description:
          'A Postman auth block sends the API key as a query-string parameter. Query strings are commonly captured in server logs, proxy logs, and browser history.',
        severity: 'high',
        confidence: 'high',
        qualifier: 'confirmed',
        file,
        evidence: `${pointerPath(site.path)} is auth type apikey with in: query`,
        recommendation:
          'Move the API key to an Authorization or custom header instead of a query-string parameter.',
      }),
    );
  }
  return findings;
}

/** A003 (Postman) — request URLs using plain http://. */
export function runNonHttpsRequestsPostman(doc: PostmanDoc, file: string): Finding[] {
  const findings: Finding[] = [];
  for (const req of doc.requests) {
    const explicitProtocol = requestUrlProtocol(req.request);
    const raw = requestUrlString(req.request);
    const scheme = explicitProtocol ?? (raw ? parseUrlish(raw)?.scheme : undefined);
    if (scheme !== 'http') continue;
    const hostname = requestUrlHost(req.request) ?? (raw ? parseUrlish(raw)?.hostname : undefined);
    const local = isLocalHost(hostname);
    findings.push(
      buildFinding({
        ruleId: 'A003',
        title: 'Non-HTTPS request URL',
        description: `A saved request uses the plain http:// scheme${
          local
            ? ' (a localhost/loopback address — likely a local dev server, lower real-world risk)'
            : ''
        }. Plain HTTP transmits requests, responses, and any credentials unencrypted.`,
        severity: local ? 'info' : 'medium',
        confidence: 'high',
        qualifier: 'confirmed',
        file,
        evidence: `${pointerPath([...req.itemPath, 'request', 'url'])} ("${req.namePath.join(' / ')}") uses http://${raw ? ` (${raw})` : ''}`,
        recommendation: 'Use https:// for all requests in the collection.',
      }),
    );
  }
  return findings;
}

/** A008 (Postman) — OAuth1 and HTTP Digest auth types. */
export function runInsecureAuthFlowsPostman(doc: PostmanDoc, file: string): Finding[] {
  const findings: Finding[] = [];
  for (const site of doc.authSites) {
    if (site.auth.type === 'oauth1') {
      findings.push(
        buildFinding({
          ruleId: 'A008',
          title: 'OAuth1 authentication',
          description:
            'OAuth 1.0/1.0a requires per-request cryptographic signing and has been superseded by OAuth2 + TLS in virtually all modern APIs; it is often a sign of a legacy integration.',
          severity: 'medium',
          confidence: 'high',
          qualifier: 'likely',
          file,
          evidence: `${pointerPath(site.path)} is auth type oauth1`,
          recommendation:
            'Migrate to OAuth2 (authorization code + PKCE) or a bearer-token scheme over TLS.',
        }),
      );
    }
    if (site.auth.type === 'digest') {
      findings.push(
        buildFinding({
          ruleId: 'A008',
          title: 'HTTP Digest authentication',
          description:
            'HTTP Digest authentication relies on a weak challenge-response construction and lacks modern security properties.',
          severity: 'medium',
          confidence: 'high',
          qualifier: 'likely',
          file,
          evidence: `${pointerPath(site.path)} is auth type digest`,
          recommendation: 'Replace HTTP Digest with a token-based scheme (bearer/OAuth2) over TLS.',
        }),
      );
    }
  }
  return findings;
}

interface Candidate {
  key?: string;
  value: string;
  path: readonly (string | number)[];
  context: string;
}

function collectCandidates(doc: PostmanDoc): Candidate[] {
  const candidates: Candidate[] = [];

  for (const v of doc.variables) {
    if (typeof v.value === 'string') {
      candidates.push({ key: v.key, value: v.value, path: v.path, context: `variable '${v.key}'` });
    }
  }

  for (const site of doc.authSites) {
    for (const [scheme, list] of Object.entries(site.auth)) {
      if (scheme === 'type' || !Array.isArray(list)) continue;
      list.forEach((entry, i) => {
        if (
          isPlainObject(entry) &&
          typeof entry.key === 'string' &&
          typeof entry.value === 'string'
        ) {
          candidates.push({
            key: entry.key,
            value: entry.value,
            path: [...site.path, scheme, i, 'value'],
            context: `auth.${scheme} '${entry.key}'`,
          });
        }
      });
    }
  }

  for (const req of doc.requests) {
    const headers = req.request.header;
    if (Array.isArray(headers)) {
      headers.forEach((h, i) => {
        if (isPlainObject(h) && typeof h.key === 'string' && typeof h.value === 'string') {
          candidates.push({
            key: h.key,
            value: h.value,
            path: [...req.itemPath, 'request', 'header', i, 'value'],
            context: `header '${h.key}' on request '${req.namePath.join(' / ')}'`,
          });
        }
      });
    }
    for (const resp of req.responses) {
      const respHeaders = resp.value.header;
      if (Array.isArray(respHeaders)) {
        respHeaders.forEach((h, i) => {
          if (isPlainObject(h) && typeof h.key === 'string' && typeof h.value === 'string') {
            candidates.push({
              key: h.key,
              value: h.value,
              path: [...resp.path, 'header', i, 'value'],
              context: `response header '${h.key}' on request '${req.namePath.join(' / ')}'`,
            });
          }
        });
      }
      if (typeof resp.value.body === 'string') {
        const match = findTokenInText(resp.value.body);
        if (match) {
          candidates.push({
            value: match,
            path: [...resp.path, 'body'],
            context: `saved response body on request '${req.namePath.join(' / ')}'`,
          });
        }
      }
    }
  }

  return candidates;
}

/** A010 — secrets in Postman collection variables, auth blocks, headers, or saved response examples. */
export function runPostmanSecrets(doc: PostmanDoc, file: string): Finding[] {
  const findings: Finding[] = [];
  for (const candidate of collectCandidates(doc)) {
    if (looksLikePlaceholder(candidate.value)) continue;
    const shape = classifyStandaloneValue(candidate.value);
    // A templated value (e.g. "Bearer {{apiToken}}") references a variable rather than
    // embedding a literal secret; only a concrete shape match still counts as evidence.
    const templated = hasTemplateReference(candidate.value);
    const nameHints = !templated && candidate.key !== undefined && keyLooksSecret(candidate.key);
    if (!shape && !nameHints) continue;

    findings.push(
      buildFinding({
        ruleId: 'A010',
        title: 'Possible secret in Postman collection',
        description:
          'A Postman collection value looks like a live credential or token (matches a known token format, or a credential-like name holding a non-placeholder value) rather than a placeholder or variable reference.',
        severity: 'high',
        confidence: shape?.confidence ?? 'medium',
        qualifier: 'likely',
        file,
        evidence: redactEvidence(
          `${pointerPath(candidate.path)} (${candidate.context}) = ${candidate.value}`,
          [candidate.value],
        ),
        recommendation:
          'Remove the literal secret from the collection; reference a Postman vault/environment secret variable instead, and rotate the exposed credential.',
      }),
    );
  }
  return findings;
}
