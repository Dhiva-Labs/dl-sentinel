import type { NormalizedApiDoc, NormalizedOperation, SecurityScheme } from './internal-types.js';
import type { PathSegment } from './pointer.js';
import { HTTP_METHODS } from './util.js';
import { isPlainObject } from './util.js';

function extractSecuritySchemes(
  root: Record<string, unknown>,
  kind: 'openapi3' | 'swagger2',
): SecurityScheme[] {
  let container: Record<string, unknown> = {};
  let basePath: PathSegment[] = [];
  if (kind === 'openapi3') {
    const components = root.components;
    if (isPlainObject(components) && isPlainObject(components.securitySchemes)) {
      container = components.securitySchemes;
      basePath = ['components', 'securitySchemes'];
    }
  } else {
    if (isPlainObject(root.securityDefinitions)) {
      container = root.securityDefinitions;
      basePath = ['securityDefinitions'];
    }
  }
  const schemes: SecurityScheme[] = [];
  for (const [name, raw] of Object.entries(container)) {
    if (!isPlainObject(raw)) continue;
    schemes.push({
      name,
      type: typeof raw.type === 'string' ? raw.type : undefined,
      in: typeof raw.in === 'string' ? raw.in : undefined,
      scheme: typeof raw.scheme === 'string' ? raw.scheme : undefined,
      flow: typeof raw.flow === 'string' ? raw.flow : undefined,
      flows: isPlainObject(raw.flows) ? raw.flows : undefined,
      paramName: typeof raw.name === 'string' ? raw.name : undefined,
      path: [...basePath, name],
    });
  }
  return schemes;
}

function extractServers(
  root: Record<string, unknown>,
  kind: 'openapi3' | 'swagger2',
): Array<{ url: string; path: readonly PathSegment[] }> {
  const servers: Array<{ url: string; path: readonly PathSegment[] }> = [];
  if (kind === 'openapi3') {
    const list = root.servers;
    if (Array.isArray(list)) {
      list.forEach((entry, i) => {
        if (isPlainObject(entry) && typeof entry.url === 'string') {
          servers.push({ url: entry.url, path: ['servers', i, 'url'] });
        }
      });
    }
  } else {
    const schemes = root.schemes;
    const host = typeof root.host === 'string' ? root.host : 'unknown-host';
    if (Array.isArray(schemes)) {
      schemes.forEach((scheme, i) => {
        if (typeof scheme === 'string') {
          servers.push({ url: `${scheme}://${host}`, path: ['schemes', i] });
        }
      });
    }
  }
  return servers;
}

function mergeParameters(shared: unknown, own: unknown): Record<string, unknown>[] {
  const merged = new Map<string, Record<string, unknown>>();
  const add = (list: unknown): void => {
    if (!Array.isArray(list)) return;
    for (const p of list) {
      if (!isPlainObject(p)) continue;
      const key = `${String(p.in ?? '')}:${String(p.name ?? '')}`;
      merged.set(key, p);
    }
  };
  add(shared);
  add(own);
  return [...merged.values()];
}

function extractOperations(root: Record<string, unknown>): NormalizedOperation[] {
  const operations: NormalizedOperation[] = [];
  const paths = root.paths;
  if (!isPlainObject(paths)) return operations;
  for (const [pathKey, pathItemRaw] of Object.entries(paths)) {
    if (!isPlainObject(pathItemRaw)) continue;
    const pathItem = pathItemRaw;
    const sharedParameters = pathItem.parameters;
    for (const method of HTTP_METHODS) {
      const operationRaw = pathItem[method];
      if (!isPlainObject(operationRaw)) continue;
      const hasOwnSecurity = Object.prototype.hasOwnProperty.call(operationRaw, 'security');
      const ownSecurityRaw = operationRaw.security;
      operations.push({
        path: pathKey,
        method,
        operation: operationRaw,
        parameters: mergeParameters(sharedParameters, operationRaw.parameters),
        hasOwnSecurity,
        ownSecurity: Array.isArray(ownSecurityRaw)
          ? ownSecurityRaw
          : hasOwnSecurity
            ? []
            : undefined,
        opPath: ['paths', pathKey, method],
      });
    }
  }
  return operations;
}

export function normalizeApiDoc(
  root: Record<string, unknown>,
  kind: 'openapi3' | 'swagger2',
): NormalizedApiDoc {
  const hasGlobalSecurity = Object.prototype.hasOwnProperty.call(root, 'security');
  const globalSecurityRaw = root.security;
  return {
    kind,
    root,
    securitySchemes: extractSecuritySchemes(root, kind),
    hasGlobalSecurity,
    globalSecurity: Array.isArray(globalSecurityRaw) ? globalSecurityRaw : undefined,
    servers: extractServers(root, kind),
    operations: extractOperations(root),
  };
}
