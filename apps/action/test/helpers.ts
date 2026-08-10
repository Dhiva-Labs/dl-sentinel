import type { ActionIO, FetchInitLike, FetchResponseLike } from '../src/io.js';

export interface RecordedRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string | undefined;
}

export interface FakeFetch {
  fetch: ActionIO['fetch'];
  requests: RecordedRequest[];
}

export interface FakeFetchConfig {
  /** JSON returned by the GET list-comments call. Default `[]`. */
  listComments?: unknown;
  /** Status for the GET. Default 200. */
  listStatus?: number;
  /** Status for the POST/PATCH write. Default 201. */
  writeStatus?: number;
  /** JSON returned by the write. Default `{ id: 12345 }`. */
  writeBody?: unknown;
}

function response(status: number, data: unknown): FetchResponseLike {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(data),
    text: () => Promise.resolve(typeof data === 'string' ? data : JSON.stringify(data)),
  };
}

/** A fetch that records every request and returns canned responses. Never hits the network. */
export function fakeFetch(config: FakeFetchConfig = {}): FakeFetch {
  const requests: RecordedRequest[] = [];
  const fetch = (url: string, init?: FetchInitLike): Promise<FetchResponseLike> => {
    const method = (init?.method ?? 'GET').toUpperCase();
    requests.push({ url, method, headers: init?.headers ?? {}, body: init?.body });
    if (method === 'GET') {
      return Promise.resolve(response(config.listStatus ?? 200, config.listComments ?? []));
    }
    return Promise.resolve(response(config.writeStatus ?? 201, config.writeBody ?? { id: 12345 }));
  };
  return { fetch, requests };
}

/** A fetch that fails the test if it is ever called (asserts "no network"). */
export function throwingFetch(): ActionIO['fetch'] {
  return () => Promise.reject(new Error('fetch must not be called'));
}

export interface Captured {
  io: ActionIO;
  out(): string;
  err(): string;
}

/** Build an ActionIO capturing stdout/stderr into strings. */
export function captureIO(env: NodeJS.ProcessEnv, fetch: ActionIO['fetch']): Captured {
  let out = '';
  let err = '';
  const io: ActionIO = {
    env,
    stdout: (text) => {
      out += text;
    },
    stderr: (text) => {
      err += text;
    },
    fetch,
  };
  return { io, out: () => out, err: () => err };
}
