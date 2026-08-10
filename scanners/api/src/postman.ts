import type { PathSegment } from './pointer.js';
import { isPlainObject } from './util.js';

export interface PostmanVariable {
  key: string;
  value: unknown;
  path: readonly PathSegment[];
}

export interface PostmanResponseExample {
  value: Record<string, unknown>;
  path: readonly PathSegment[];
}

export interface PostmanRequestNode {
  namePath: readonly string[];
  itemPath: readonly PathSegment[];
  request: Record<string, unknown>;
  /** Effective auth for this request: own request.auth, else nearest ancestor folder/collection auth. */
  auth: Record<string, unknown> | undefined;
  authPath: readonly PathSegment[] | undefined;
  responses: PostmanResponseExample[];
}

export interface PostmanAuthSite {
  auth: Record<string, unknown>;
  path: readonly PathSegment[];
}

export interface PostmanDoc {
  root: Record<string, unknown>;
  variables: PostmanVariable[];
  requests: PostmanRequestNode[];
  /** Every distinct place an `auth` object is literally declared (collection/folder/request). */
  authSites: PostmanAuthSite[];
}

function collectVariables(
  container: Record<string, unknown>,
  path: readonly PathSegment[],
  out: PostmanVariable[],
): void {
  const variable = container.variable;
  if (!Array.isArray(variable)) return;
  variable.forEach((entry, i) => {
    if (isPlainObject(entry) && typeof entry.key === 'string') {
      out.push({ key: entry.key, value: entry.value, path: [...path, 'variable', i] });
    }
  });
}

function collectResponses(
  item: Record<string, unknown>,
  path: readonly PathSegment[],
): PostmanResponseExample[] {
  const responses: PostmanResponseExample[] = [];
  const response = item.response;
  if (Array.isArray(response)) {
    response.forEach((entry, i) => {
      if (isPlainObject(entry)) {
        responses.push({ value: entry, path: [...path, 'response', i] });
      }
    });
  }
  return responses;
}

function walkItems(
  items: unknown,
  path: readonly PathSegment[],
  namePath: readonly string[],
  ancestorAuth: Record<string, unknown> | undefined,
  ancestorAuthPath: readonly PathSegment[] | undefined,
  variables: PostmanVariable[],
  requests: PostmanRequestNode[],
  authSites: PostmanAuthSite[],
): void {
  if (!Array.isArray(items)) return;
  items.forEach((item, i) => {
    if (!isPlainObject(item)) return;
    const itemPath = [...path, i];
    const name = typeof item.name === 'string' ? item.name : `#${i}`;
    const nextNamePath = [...namePath, name];
    collectVariables(item, itemPath, variables);

    const ownFolderAuth = isPlainObject(item.auth) ? item.auth : undefined;
    if (ownFolderAuth) authSites.push({ auth: ownFolderAuth, path: [...itemPath, 'auth'] });
    const folderAuth = ownFolderAuth ?? ancestorAuth;
    const folderAuthPath = ownFolderAuth ? [...itemPath, 'auth'] : ancestorAuthPath;

    if (Array.isArray(item.item)) {
      // Folder: recurse.
      walkItems(
        item.item,
        [...itemPath, 'item'],
        nextNamePath,
        folderAuth,
        folderAuthPath,
        variables,
        requests,
        authSites,
      );
      return;
    }

    if (isPlainObject(item.request)) {
      const request = item.request;
      const requestAuth = isPlainObject(request.auth) ? request.auth : undefined;
      if (requestAuth)
        authSites.push({ auth: requestAuth, path: [...itemPath, 'request', 'auth'] });
      const effectiveAuth = requestAuth ?? folderAuth;
      const effectiveAuthPath = requestAuth ? [...itemPath, 'request', 'auth'] : folderAuthPath;
      requests.push({
        namePath: nextNamePath,
        itemPath,
        request,
        auth: effectiveAuth,
        authPath: effectiveAuthPath,
        responses: collectResponses(item, itemPath),
      });
    }
  });
}

export function normalizePostmanDoc(root: Record<string, unknown>): PostmanDoc {
  const variables: PostmanVariable[] = [];
  const requests: PostmanRequestNode[] = [];
  const authSites: PostmanAuthSite[] = [];
  collectVariables(root, [], variables);
  const collectionAuth = isPlainObject(root.auth) ? root.auth : undefined;
  const collectionAuthPath = collectionAuth ? (['auth'] as PathSegment[]) : undefined;
  if (collectionAuth) authSites.push({ auth: collectionAuth, path: ['auth'] });
  walkItems(
    root.item,
    ['item'],
    [],
    collectionAuth,
    collectionAuthPath,
    variables,
    requests,
    authSites,
  );
  return { root, variables, requests, authSites };
}

/** Extract a Postman auth-scheme sub-value list (e.g. auth.apikey) as key->value pairs. */
export function authParamValue(auth: Record<string, unknown>, type: string, key: string): unknown {
  const list = auth[type];
  if (!Array.isArray(list)) return undefined;
  for (const entry of list) {
    if (isPlainObject(entry) && entry.key === key) return entry.value;
  }
  return undefined;
}

/** Best-effort raw URL string from a Postman request's `url` field (string or url object). */
export function requestUrlString(request: Record<string, unknown>): string | undefined {
  const url = request.url;
  if (typeof url === 'string') return url;
  if (isPlainObject(url)) {
    if (typeof url.raw === 'string') return url.raw;
  }
  return undefined;
}

/** Explicit protocol field on a Postman url object, when present. */
export function requestUrlProtocol(request: Record<string, unknown>): string | undefined {
  const url = request.url;
  if (isPlainObject(url) && typeof url.protocol === 'string') return url.protocol;
  return undefined;
}

/** Hostname from a Postman url object's `host` array (joined with '.'), when present. */
export function requestUrlHost(request: Record<string, unknown>): string | undefined {
  const url = request.url;
  if (isPlainObject(url) && Array.isArray(url.host)) {
    return url.host.filter((p): p is string => typeof p === 'string').join('.');
  }
  return undefined;
}
