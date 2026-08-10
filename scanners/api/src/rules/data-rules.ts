import type { Finding } from '@dl-sentinel/core';
import { buildFinding } from '../build-finding.js';
import type { NormalizedApiDoc } from '../internal-types.js';
import { isLocalRef, isRefNode, resolveLocalRef } from '../ref.js';
import { pointerPath, type PathSegment } from '../pointer.js';
import { walkSchema } from '../schema-walk.js';
import { isPlainObject } from '../util.js';

const SENSITIVE_SUBSTRINGS = [
  'password',
  'secret',
  'token',
  'apikey',
  'ssn',
  'creditcard',
  'cardnumber',
];

function normalizeFieldName(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]/g, '');
}

function matchSensitiveName(name: string): string | undefined {
  const normalized = normalizeFieldName(name);
  return SENSITIVE_SUBSTRINGS.find((s) => normalized.includes(s));
}

function resolveMaybeRef(node: unknown, root: unknown): unknown {
  if (isRefNode(node)) {
    if (!isLocalRef(node.$ref)) return undefined; // external/network ref: noted-and-skipped
    return resolveLocalRef(root, node.$ref);
  }
  return node;
}

/** A006 — 2xx response schemas exposing fields whose name suggests sensitive data. */
export function runSensitiveResponseData(doc: NormalizedApiDoc, file: string): Finding[] {
  const findings: Finding[] = [];
  for (const op of doc.operations) {
    const responses = op.operation.responses;
    if (!isPlainObject(responses)) continue;
    for (const [status, responseRaw] of Object.entries(responses)) {
      if (!/^2\d\d$/.test(status)) continue;
      const response = resolveMaybeRef(responseRaw, doc.root);
      if (!isPlainObject(response)) continue;

      const schemaEntries: Array<{ schema: unknown; path: readonly PathSegment[] }> = [];
      if (doc.kind === 'openapi3' && isPlainObject(response.content)) {
        for (const [mediaType, media] of Object.entries(response.content)) {
          if (isPlainObject(media) && media.schema !== undefined) {
            schemaEntries.push({
              schema: media.schema,
              path: [...op.opPath, 'responses', status, 'content', mediaType, 'schema'],
            });
          }
        }
      } else if (doc.kind === 'swagger2' && response.schema !== undefined) {
        schemaEntries.push({
          schema: response.schema,
          path: [...op.opPath, 'responses', status, 'schema'],
        });
      }

      for (const entry of schemaEntries) {
        const seen = new Set<string>();
        walkSchema(
          entry.schema,
          doc.root,
          (visit) => {
            if (!visit.propertyName) return;
            const matched = matchSensitiveName(visit.propertyName);
            if (!matched) return;
            const key = pointerPath(visit.path);
            if (seen.has(key)) return;
            seen.add(key);
            findings.push(
              buildFinding({
                ruleId: 'A006',
                title: 'Sensitive field name in response schema',
                description:
                  'A 2xx response schema declares a field whose name suggests it returns sensitive data (e.g. a password, token, secret, or card number) to API clients.',
                severity: 'medium',
                confidence: 'medium',
                qualifier: 'likely',
                file,
                evidence: `${key} — field name suggests sensitive data (matched "${matched}")`,
                recommendation:
                  'Avoid returning credentials or secrets in API responses. If intentional, ensure the field is never logged and document the exposure explicitly.',
              }),
            );
          },
          entry.path,
        );
      }
    }
  }
  return findings;
}

interface UnconstrainedHit {
  path: readonly PathSegment[];
}

function checkConstraintNode(
  node: Record<string, unknown>,
  path: readonly PathSegment[],
  hits: UnconstrainedHit[],
): void {
  const type = node.type;
  if (type === 'string') {
    const constrained =
      node.maxLength !== undefined ||
      node.pattern !== undefined ||
      node.enum !== undefined ||
      node.format !== undefined;
    if (!constrained) hits.push({ path });
  } else if (type === 'number' || type === 'integer') {
    const constrained =
      node.maximum !== undefined ||
      node.minimum !== undefined ||
      node.exclusiveMaximum !== undefined ||
      node.exclusiveMinimum !== undefined ||
      node.enum !== undefined;
    if (!constrained) hits.push({ path });
  }
}

function parameterSchema(param: Record<string, unknown>, kind: 'openapi3' | 'swagger2'): unknown {
  if (kind === 'openapi3') {
    if (isPlainObject(param.schema)) return param.schema;
    const content = param.content;
    if (isPlainObject(content)) {
      const first = Object.values(content)[0];
      if (isPlainObject(first) && first.schema !== undefined) return first.schema;
    }
    return undefined;
  }
  // Swagger 2 non-body parameters carry type/format/etc. directly on the parameter object.
  return param;
}

/** A009 — unconstrained writable string/numeric fields across request parameters + bodies (aggregated). */
export function runUnconstrainedParameters(doc: NormalizedApiDoc, file: string): Finding[] {
  const hits: UnconstrainedHit[] = [];

  for (const op of doc.operations) {
    for (const param of op.parameters) {
      const inLocation = typeof param.in === 'string' ? param.in : undefined;
      if (inLocation === 'path') continue; // identifiers, excluded to avoid flood on routine REST paths
      if (inLocation === 'body') continue; // handled via requestBody-style walk below
      const schema = parameterSchema(param, doc.kind);
      if (schema === undefined) continue;
      const paramName = typeof param.name === 'string' ? param.name : '?';
      walkSchema(schema, doc.root, (visit) => checkConstraintNode(visit.node, visit.path, hits), [
        ...op.opPath,
        'parameters',
        paramName,
      ]);
    }

    if (doc.kind === 'swagger2') {
      const bodyParam = op.parameters.find((p) => p.in === 'body');
      if (bodyParam && bodyParam.schema !== undefined) {
        walkSchema(
          bodyParam.schema,
          doc.root,
          (visit) => checkConstraintNode(visit.node, visit.path, hits),
          [...op.opPath, 'requestBody'],
        );
      }
    } else {
      const requestBody = resolveMaybeRef(op.operation.requestBody, doc.root);
      if (isPlainObject(requestBody) && isPlainObject(requestBody.content)) {
        for (const [mediaType, media] of Object.entries(requestBody.content)) {
          if (isPlainObject(media) && media.schema !== undefined) {
            walkSchema(
              media.schema,
              doc.root,
              (visit) => checkConstraintNode(visit.node, visit.path, hits),
              [...op.opPath, 'requestBody', mediaType],
            );
          }
        }
      }
    }
  }

  if (hits.length === 0) return [];

  const examples = hits.slice(0, 5).map((h) => pointerPath(h.path));
  const remaining = hits.length - examples.length;
  // Put the count / "more" summary BEFORE the (potentially long) example path
  // list: evidence is capped at ~200 chars by redactEvidence, and truncation
  // must never eat the summary — only the tail of the example list.
  const evidence = `${hits.length} unconstrained field(s)${remaining > 0 ? ` (${remaining} more not shown)` : ''}, e.g. ${examples.join(', ')}`;
  return [
    buildFinding({
      ruleId: 'A009',
      title: 'Unconstrained writable string/numeric fields',
      description:
        'Request parameters or request body fields of type string/number/integer declare no bound (maxLength/pattern/enum/format for strings; maximum/minimum for numbers), allowing arbitrarily large or malformed input.',
      severity: 'low',
      confidence: 'medium',
      qualifier: 'potential',
      file,
      evidence,
      recommendation:
        'Add maxLength/pattern/enum/format to string fields and maximum/minimum to numeric fields, especially on writable request data.',
      metadata: { count: hits.length },
    }),
  ];
}
