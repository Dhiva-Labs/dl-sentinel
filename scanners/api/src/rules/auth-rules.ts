import type { Finding } from '@dl-sentinel/core';
import { buildFinding } from '../build-finding.js';
import type { Locator, NormalizedApiDoc } from '../internal-types.js';
import { pointerPath } from '../pointer.js';
import { isPlainObject, STATE_CHANGING_METHODS } from '../util.js';

/** A001 — no authentication defined anywhere, or a specific operation has none while schemes exist. */
export function runNoAuthDefined(doc: NormalizedApiDoc, file: string, locator: Locator): Finding[] {
  const findings: Finding[] = [];
  const noSchemes = doc.securitySchemes.length === 0;
  const noOperationHasOwnSecurity = doc.operations.every((op) => !op.hasOwnSecurity);

  if (noSchemes && !doc.hasGlobalSecurity && noOperationHasOwnSecurity) {
    const schemesField =
      doc.kind === 'openapi3' ? 'components.securitySchemes' : 'securityDefinitions';
    findings.push(
      buildFinding({
        ruleId: 'A001',
        title: 'No authentication defined',
        description:
          'The API definition declares no security schemes and no security requirement (global or per-operation) anywhere in the document.',
        severity: 'high',
        confidence: 'high',
        qualifier: 'confirmed',
        file,
        evidence: `${schemesField} is absent/empty and no "security" requirement appears anywhere in the document`,
        recommendation:
          'Define a security scheme (bearer token, OAuth2, or a header-based API key) and require it globally or on every operation.',
      }),
    );
    return findings; // Whole-document case; per-operation noise would be redundant.
  }

  if (doc.securitySchemes.length > 0 && !doc.hasGlobalSecurity) {
    for (const op of doc.operations) {
      const effectiveEmpty = !op.hasOwnSecurity || (op.ownSecurity?.length ?? 0) === 0;
      if (!effectiveEmpty) continue;
      const loc = locator.locate(op.opPath);
      findings.push(
        buildFinding({
          ruleId: 'A001',
          title: 'Operation has no effective security requirement',
          description:
            'Security schemes are defined in this document, but this operation has no security requirement of its own and there is no global default to fall back on.',
          severity: 'high',
          confidence: 'high',
          qualifier: 'likely',
          file,
          line: loc.line,
          column: loc.column,
          evidence: `${pointerPath(op.opPath)} (${op.method.toUpperCase()} ${op.path}) has no security requirement and no global default is defined`,
          recommendation:
            'Add a security requirement to this operation, or define a global default security requirement.',
        }),
      );
    }
  }

  return findings;
}

/** A002 — apiKey security scheme transmitted via the query string (OpenAPI 3 / Swagger 2). */
export function runApiKeyInQuery(doc: NormalizedApiDoc, file: string, locator: Locator): Finding[] {
  const findings: Finding[] = [];
  for (const scheme of doc.securitySchemes) {
    if (scheme.type !== 'apiKey' || scheme.in !== 'query') continue;
    const loc = locator.locate(scheme.path);
    findings.push(
      buildFinding({
        ruleId: 'A002',
        title: 'API key transmitted via query string',
        description:
          'A security scheme sends the API key as a query-string parameter. Query strings are commonly captured in server logs, proxy logs, and browser history, and can leak via the Referer header.',
        severity: 'high',
        confidence: 'high',
        qualifier: 'confirmed',
        file,
        line: loc.line,
        column: loc.column,
        evidence: `${pointerPath(scheme.path)} is type apiKey, in: query${scheme.paramName ? ` (param: ${scheme.paramName})` : ''}`,
        recommendation:
          'Move the API key to an Authorization or custom header instead of a query-string parameter.',
      }),
    );
  }
  return findings;
}

/** A004 — HTTP Basic authentication scheme declared. */
export function runHttpBasicAuth(doc: NormalizedApiDoc, file: string, locator: Locator): Finding[] {
  const findings: Finding[] = [];
  for (const scheme of doc.securitySchemes) {
    const isBasic =
      doc.kind === 'openapi3'
        ? scheme.type === 'http' && (scheme.scheme ?? '').toLowerCase() === 'basic'
        : scheme.type === 'basic';
    if (!isBasic) continue;
    const loc = locator.locate(scheme.path);
    findings.push(
      buildFinding({
        ruleId: 'A004',
        title: 'HTTP Basic authentication scheme',
        description:
          'The document declares an HTTP Basic authentication scheme. Basic auth sends credentials base64-encoded (not encrypted) on every request and has no standard support for scoping, rotation, or revocation.',
        severity: 'medium',
        confidence: 'high',
        qualifier: 'likely',
        file,
        line: loc.line,
        column: loc.column,
        evidence: `${pointerPath(scheme.path)} is ${doc.kind === 'openapi3' ? 'type http, scheme basic' : 'type basic'}`,
        recommendation:
          'Replace HTTP Basic with a token-based scheme (bearer/OAuth2) and require TLS.',
      }),
    );
  }
  return findings;
}

/** A005 — state-changing operation (POST/PUT/PATCH/DELETE) without effective security. */
export function runStateChangingWithoutAuth(
  doc: NormalizedApiDoc,
  file: string,
  locator: Locator,
): Finding[] {
  const findings: Finding[] = [];
  const globalHasEntries = (doc.globalSecurity?.length ?? 0) > 0;
  for (const op of doc.operations) {
    if (!STATE_CHANGING_METHODS.has(op.method)) continue;
    const effectiveSecurity = op.hasOwnSecurity ? op.ownSecurity : doc.globalSecurity;
    const hasEffective = Array.isArray(effectiveSecurity) && effectiveSecurity.length > 0;
    if (hasEffective) continue;

    const isExplicitOverride =
      op.hasOwnSecurity &&
      (op.ownSecurity?.length ?? 0) === 0 &&
      doc.hasGlobalSecurity &&
      globalHasEntries;
    const loc = locator.locate(op.opPath);
    findings.push(
      buildFinding({
        ruleId: 'A005',
        title: 'State-changing operation without security',
        description: `The ${op.method.toUpperCase()} operation performs a state-changing action but has no effective security requirement.`,
        severity: 'high',
        confidence: 'high',
        qualifier: isExplicitOverride ? 'confirmed' : 'likely',
        file,
        line: loc.line,
        column: loc.column,
        evidence: `${pointerPath(op.opPath)} (${op.method.toUpperCase()} ${op.path}) has no effective security${
          isExplicitOverride ? ' — explicit "security: []" overrides the global requirement' : ''
        }`,
        recommendation:
          'Require authentication on this operation (operation-level or inherited global security) before allowing state changes.',
      }),
    );
  }
  return findings;
}

/** A008 — deprecated/insecure auth flows: OAuth2 implicit flow, HTTP Digest (OpenAPI 3 / Swagger 2). */
export function runInsecureAuthFlows(
  doc: NormalizedApiDoc,
  file: string,
  locator: Locator,
): Finding[] {
  const findings: Finding[] = [];
  for (const scheme of doc.securitySchemes) {
    if (scheme.type === 'oauth2') {
      const isImplicit =
        doc.kind === 'openapi3'
          ? isPlainObject(scheme.flows) && isPlainObject(scheme.flows.implicit)
          : scheme.flow === 'implicit';
      if (isImplicit) {
        const loc = locator.locate(scheme.path);
        findings.push(
          buildFinding({
            ruleId: 'A008',
            title: 'OAuth2 implicit flow',
            description:
              'The OAuth2 implicit flow returns access tokens directly in a URL fragment/redirect with no client authentication, and is deprecated by OAuth 2.0 Security Best Current Practice in favor of authorization code + PKCE.',
            severity: 'medium',
            confidence: 'high',
            qualifier: 'likely',
            file,
            line: loc.line,
            column: loc.column,
            evidence: `${pointerPath(scheme.path)} defines an OAuth2 implicit flow`,
            recommendation: 'Migrate to the authorization code flow with PKCE.',
          }),
        );
      }
    }
    if (
      doc.kind === 'openapi3' &&
      scheme.type === 'http' &&
      (scheme.scheme ?? '').toLowerCase() === 'digest'
    ) {
      const loc = locator.locate(scheme.path);
      findings.push(
        buildFinding({
          ruleId: 'A008',
          title: 'HTTP Digest authentication scheme',
          description:
            'HTTP Digest authentication relies on a weak challenge-response construction and lacks modern security properties (no forward secrecy, weak hashing in common implementations).',
          severity: 'medium',
          confidence: 'high',
          qualifier: 'likely',
          file,
          line: loc.line,
          column: loc.column,
          evidence: `${pointerPath(scheme.path)} is type http, scheme digest`,
          recommendation: 'Replace HTTP Digest with a token-based scheme (bearer/OAuth2) over TLS.',
        }),
      );
    }
  }
  return findings;
}
