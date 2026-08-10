import type { IncomingMessage, ServerResponse } from 'node:http';
import type { ErrorCode, ServerLogger } from './types.js';

/**
 * An error carrying an HTTP status, a structured error code, and optional
 * response headers. Handlers throw these; the server turns them into the
 * `{ error: { code, message } }` envelope. Messages are safe to show clients —
 * they never contain stack traces or secret material.
 */
export class HttpError extends Error {
  readonly status: number;
  readonly code: ErrorCode;
  readonly headers: Record<string, string>;

  constructor(
    status: number,
    code: ErrorCode,
    message: string,
    headers: Record<string, string> = {},
  ) {
    super(message);
    this.name = 'HttpError';
    this.status = status;
    this.code = code;
    this.headers = headers;
  }
}

export function methodNotAllowed(allow: string): HttpError {
  return new HttpError(405, 'method_not_allowed', `Method not allowed. Allowed: ${allow}`, {
    Allow: allow,
  });
}

export function notFound(message = 'Not found'): HttpError {
  return new HttpError(404, 'not_found', message);
}

/**
 * The caller authenticated but their role does not permit this request. Kept
 * distinct from 401 (missing, invalid, or disabled token) so a client can tell
 * "set a token" apart from "you may not do this". Naming the required role is
 * not a leak — the permission matrix is public in docs/api.md.
 */
export function forbidden(required: string): HttpError {
  return new HttpError(
    403,
    'forbidden',
    `Your role does not permit this request (requires role: ${required})`,
  );
}

/**
 * A scan exists but has not completed, so a finished-report endpoint cannot serve
 * it. Applies to queued/running (retry later) and failed (no report will exist);
 * the current status is included so callers can decide what to do.
 */
export function scanNotReady(status: string): HttpError {
  return new HttpError(
    409,
    'scan_not_ready',
    `No completed report is available for this scan (status: ${status})`,
  );
}

const SECURITY_HEADERS: Record<string, string> = {
  'X-Content-Type-Options': 'nosniff',
};

/** Send a JSON body with the given status. */
export function sendJson(
  res: ServerResponse,
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload),
    ...SECURITY_HEADERS,
    ...headers,
  });
  res.end(payload);
}

/** Send an already-rendered string body with an explicit content type. */
export function sendText(
  res: ServerResponse,
  status: number,
  body: string,
  contentType: string,
  headers: Record<string, string> = {},
): void {
  res.writeHead(status, {
    'Content-Type': contentType,
    'Content-Length': Buffer.byteLength(body),
    ...SECURITY_HEADERS,
    ...headers,
  });
  res.end(body);
}

/** Send a 204 No Content response (used for successful DELETEs). */
export function sendNoContent(res: ServerResponse, headers: Record<string, string> = {}): void {
  res.writeHead(204, { ...SECURITY_HEADERS, ...headers });
  res.end();
}

/** Send the structured error envelope for an {@link HttpError}. */
export function sendHttpError(res: ServerResponse, error: HttpError): void {
  sendJson(
    res,
    error.status,
    { error: { code: error.code, message: error.message } },
    error.headers,
  );
}

/**
 * Turn any thrown value into a response. {@link HttpError} is sent as-is; any
 * other error becomes a generic 500 with the stack logged server-side only —
 * stack traces and internal messages are never leaked to clients.
 */
export function sendError(res: ServerResponse, error: unknown, logger: ServerLogger): void {
  if (res.headersSent || res.writableEnded) {
    // Response already started (e.g. a stream failed mid-flight); just close.
    if (!res.writableEnded) res.destroy();
    return;
  }
  if (error instanceof HttpError) {
    sendHttpError(res, error);
    return;
  }
  logger.error(
    `Unhandled error: ${error instanceof Error ? (error.stack ?? error.message) : String(error)}`,
  );
  sendJson(res, 500, { error: { code: 'internal_error', message: 'Internal server error' } });
}

/**
 * Read the request body, bounded to `maxBytes`. Rejects with a 413
 * {@link HttpError} if the declared or streamed size exceeds the limit.
 */
export function readBody(req: IncomingMessage, maxBytes: number): Promise<Buffer> {
  const tooLarge = (): HttpError =>
    new HttpError(413, 'payload_too_large', `Request body exceeds ${maxBytes} bytes`);

  return new Promise<Buffer>((resolve, reject) => {
    const declared = Number(req.headers['content-length']);
    if (Number.isFinite(declared) && declared > maxBytes) {
      // Drain and discard the incoming body so the 413 response is still
      // deliverable, then reject.
      req.resume();
      reject(tooLarge());
      return;
    }

    const chunks: Buffer[] = [];
    let size = 0;
    let settled = false;
    const settle = (fn: () => void): void => {
      if (settled) return;
      settled = true;
      fn();
    };

    req.on('data', (chunk: Buffer) => {
      if (settled) return;
      size += chunk.length;
      if (size > maxBytes) {
        settle(() => reject(tooLarge()));
        // Discard the remainder so the response can still be sent cleanly.
        req.resume();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => settle(() => resolve(Buffer.concat(chunks))));
    req.on('error', (err) => settle(() => reject(err)));
  });
}

/**
 * Read and JSON-parse the request body. An empty body resolves to `undefined`
 * (callers validate required fields); a non-empty invalid body rejects 400.
 */
export async function readJsonBody(req: IncomingMessage, maxBytes: number): Promise<unknown> {
  const raw = (await readBody(req, maxBytes)).toString('utf8');
  if (raw.trim() === '') return undefined;
  try {
    return JSON.parse(raw);
  } catch {
    throw new HttpError(400, 'invalid_json', 'Request body is not valid JSON');
  }
}
