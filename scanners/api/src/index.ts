import { sortFindings } from '@dl-sentinel/core';
import type { Finding, RuleMeta, ScanContext, ScannerPlugin } from '@dl-sentinel/core';
import { parseCandidate } from './parse.js';
import { normalizeApiDoc } from './openapi-normalize.js';
import { normalizePostmanDoc } from './postman.js';
import type { ParsedDoc } from './internal-types.js';
import {
  runApiKeyInQuery,
  runHttpBasicAuth,
  runInsecureAuthFlows,
  runNoAuthDefined,
  runStateChangingWithoutAuth,
} from './rules/auth-rules.js';
import { runNonHttpsServers } from './rules/transport-rules.js';
import { runSensitiveResponseData, runUnconstrainedParameters } from './rules/data-rules.js';
import { runMissingRateLimitSignal } from './rules/rate-limit-rule.js';
import {
  runApiKeyInQueryPostman,
  runInsecureAuthFlowsPostman,
  runNonHttpsRequestsPostman,
  runPostmanSecrets,
} from './rules/postman-rules.js';

const rules: RuleMeta[] = [
  {
    id: 'A001',
    title: 'No authentication defined',
    severity: 'high',
    defaultConfidence: 'high',
    category: 'api',
    description:
      'No security schemes and no security requirements are defined anywhere in the document, or a specific operation has no effective security while schemes exist elsewhere and no global default applies.',
    recommendation:
      'Define an authentication scheme and require it globally or on every operation that needs it.',
    references: [],
    compliance: { cwe: ['CWE-306'], owasp: ['A07:2021'] },
  },
  {
    id: 'A002',
    title: 'API key transmitted via query string',
    severity: 'high',
    defaultConfidence: 'high',
    category: 'api',
    description:
      'An apiKey security scheme (OpenAPI/Swagger) or apikey auth block (Postman) is configured to send the key as a query-string parameter.',
    recommendation:
      'Send the API key via an Authorization or custom header instead of a query-string parameter.',
    references: [],
    compliance: { cwe: ['CWE-598'], owasp: ['A04:2021'] },
  },
  {
    id: 'A003',
    title: 'Non-HTTPS server or request URL',
    severity: 'medium',
    defaultConfidence: 'high',
    category: 'api',
    description:
      'A server URL (OpenAPI), scheme entry (Swagger 2), or saved request URL (Postman) uses plain http://. Localhost/loopback addresses are downgraded to informational.',
    recommendation: 'Serve and call the API only over https://.',
    references: [],
    compliance: { cwe: ['CWE-319'], owasp: ['A02:2021'] },
  },
  {
    id: 'A004',
    title: 'HTTP Basic authentication scheme',
    severity: 'medium',
    defaultConfidence: 'high',
    category: 'api',
    description:
      'An HTTP Basic authentication scheme is declared. Basic auth sends credentials base64-encoded on every request.',
    recommendation: 'Replace HTTP Basic with a token-based scheme (bearer/OAuth2) over TLS.',
    references: [],
    compliance: { cwe: ['CWE-522'], owasp: ['A04:2021'] },
  },
  {
    id: 'A005',
    title: 'State-changing operation without security',
    severity: 'high',
    defaultConfidence: 'high',
    category: 'api',
    description:
      'A POST/PUT/PATCH/DELETE operation has no effective security requirement. An explicit operation-level "security: []" override of an otherwise-present global requirement is reported as confirmed.',
    recommendation: 'Require authentication on every state-changing operation.',
    references: [],
    compliance: { cwe: ['CWE-306'], owasp: ['A07:2021'] },
  },
  {
    id: 'A006',
    title: 'Sensitive field name in response schema',
    severity: 'medium',
    defaultConfidence: 'medium',
    category: 'api',
    description:
      'A 2xx response schema declares a field named like a credential or secret (password, token, secret, apiKey, ssn, creditCard, cardNumber).',
    recommendation:
      'Avoid returning credentials/secrets in API responses; document any intentional exposure explicitly.',
    references: [],
    compliance: { cwe: ['CWE-200'], owasp: ['A01:2021'] },
  },
  {
    id: 'A007',
    title: 'No rate-limit signal in the API definition',
    severity: 'low',
    defaultConfidence: 'high',
    category: 'api',
    description:
      'The document defines no 429 response and no rate-limit related header anywhere (one finding per document).',
    recommendation:
      'Document rate-limit behavior: 429 responses and/or RateLimit/X-RateLimit-* headers.',
    references: [],
    compliance: { cwe: ['CWE-799'], owasp: ['A04:2021'] },
  },
  {
    id: 'A008',
    title: 'Deprecated or insecure auth flow',
    severity: 'medium',
    defaultConfidence: 'high',
    category: 'api',
    description:
      'An OAuth2 implicit flow, OAuth1, or HTTP Digest authentication scheme is declared.',
    recommendation:
      'Migrate to OAuth2 authorization code + PKCE, or a bearer-token scheme over TLS.',
    references: [],
    compliance: { cwe: ['CWE-287'], owasp: ['A07:2021'] },
  },
  {
    id: 'A009',
    title: 'Unconstrained writable string/numeric fields',
    severity: 'low',
    defaultConfidence: 'medium',
    category: 'api',
    description:
      'Request parameters or request body fields of type string/number/integer declare no bound (aggregated into one finding per document).',
    recommendation:
      'Add maxLength/pattern/enum/format to string fields and maximum/minimum to numeric fields.',
    references: [],
    compliance: { cwe: ['CWE-20'], owasp: ['A03:2021'] },
  },
  {
    id: 'A010',
    title: 'Possible secret in Postman collection',
    severity: 'high',
    defaultConfidence: 'medium',
    category: 'api',
    description:
      'A Postman collection variable, auth block, header, or saved response example holds a value that looks like a live credential rather than a placeholder.',
    recommendation:
      'Remove literal secrets from the collection; use vault/environment variables and rotate any exposed credential.',
    references: [],
    compliance: { cwe: ['CWE-798'], owasp: ['A07:2021'] },
  },
];

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function runRulesForDoc(doc: ParsedDoc, file: string): Finding[] {
  if (doc.kind === 'postman2') {
    const postmanDoc = normalizePostmanDoc(doc.root);
    return [
      ...runApiKeyInQueryPostman(postmanDoc, file),
      ...runNonHttpsRequestsPostman(postmanDoc, file),
      ...runInsecureAuthFlowsPostman(postmanDoc, file),
      ...runPostmanSecrets(postmanDoc, file),
      ...runMissingRateLimitSignal(doc.root, file),
    ];
  }

  const normalized = normalizeApiDoc(doc.root, doc.kind);
  return [
    ...runNoAuthDefined(normalized, file, doc.locator),
    ...runApiKeyInQuery(normalized, file, doc.locator),
    ...runNonHttpsServers(normalized, file, doc.locator),
    ...runHttpBasicAuth(normalized, file, doc.locator),
    ...runStateChangingWithoutAuth(normalized, file, doc.locator),
    ...runInsecureAuthFlows(normalized, file, doc.locator),
    ...runSensitiveResponseData(normalized, file),
    ...runUnconstrainedParameters(normalized, file),
    ...runMissingRateLimitSignal(doc.root, file),
  ];
}

async function scan(context: ScanContext): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = [...context.files].sort((a, b) => a.relPath.localeCompare(b.relPath));

  for (const file of files) {
    if (context.signal.aborted) {
      throw new Error('api scanner: scan aborted');
    }

    let text: string;
    try {
      text = await context.readFile(file);
    } catch (err) {
      context.logger.warn(`api: failed to read ${file.relPath}: ${errorMessage(err)}`);
      continue;
    }

    const outcome = parseCandidate(file.relPath, text);
    if (outcome.status === 'skip') continue;
    if (outcome.status === 'error') {
      context.logger.warn(`api: skipping ${file.relPath} (unparsable: ${outcome.message})`);
      continue;
    }

    try {
      findings.push(...runRulesForDoc(outcome.doc, file.relPath));
    } catch (err) {
      context.logger.warn(`api: rule evaluation failed for ${file.relPath}: ${errorMessage(err)}`);
    }
  }

  return sortFindings(findings);
}

export const apiScanner: ScannerPlugin = {
  id: 'api',
  name: 'API Scanner',
  version: '0.1.0',
  categories: ['api'],
  supportedFiles: [
    '**/openapi.yml',
    '**/openapi.yaml',
    '**/openapi.json',
    '**/swagger.yml',
    '**/swagger.yaml',
    '**/swagger.json',
    '**/*.openapi.{yml,yaml,json}',
    '**/api-spec*.{yml,yaml,json}',
    '**/*postman_collection*.json',
    '**/*.{yml,yaml,json}',
  ],
  rules,
  scan,
};

export default apiScanner;
