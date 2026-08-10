import { createReadStream, existsSync, statSync } from 'node:fs';
import path from 'node:path';
import type { ServerResponse } from 'node:http';
import * as webModule from '@dl-sentinel/web';
import { HttpError, notFound, sendText } from './http.js';
import type { ServerLogger } from './types.js';

// The web dashboard package is built in parallel and currently a stub. Treat
// its shape defensively: it MAY export getWebRoot(): string. Never rely on the
// binding existing, and never crash if it does not.
const web: { getWebRoot?: () => string } = webModule;

const CONTENT_TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.ico': 'image/x-icon',
  '.webp': 'image/webp',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8',
};

function contentTypeFor(file: string): string {
  return CONTENT_TYPES[path.extname(file).toLowerCase()] ?? 'application/octet-stream';
}

const PLACEHOLDER_HTML = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>DL Sentinel</title>
    <style>
      body { font-family: system-ui, sans-serif; margin: 3rem auto; max-width: 40rem; padding: 0 1rem; line-height: 1.5; }
      code { background: #f2f2f2; padding: 0.1rem 0.3rem; border-radius: 3px; }
    </style>
  </head>
  <body>
    <h1>DL Sentinel API</h1>
    <p>The API server is running. The dashboard assets are not available in this build.</p>
    <p>Health check: <code>GET /health</code>. API endpoints live under <code>/api</code> and require a bearer token.</p>
  </body>
</html>
`;

export interface StaticServer {
  serve(res: ServerResponse, pathname: string): void;
}

/** Validate that a candidate path is an existing directory. */
function checkRootDir(root: string, logger: ServerLogger): string | undefined {
  if (typeof root !== 'string' || root === '') {
    logger.warn('web root is an invalid path; serving placeholder dashboard');
    return undefined;
  }
  const resolved = path.resolve(root);
  if (!existsSync(resolved) || !statSync(resolved).isDirectory()) {
    logger.warn(`web root ${resolved} is not a directory; serving placeholder dashboard`);
    return undefined;
  }
  return resolved;
}

/**
 * Resolve the dashboard asset root from `@dl-sentinel/web`, defensively. If the
 * package does not export `getWebRoot`, it throws, or the directory is missing,
 * returns `undefined` and logs a warning — the caller then serves a placeholder.
 */
function resolveWebRoot(logger: ServerLogger): string | undefined {
  if (typeof web.getWebRoot !== 'function') {
    logger.warn('@dl-sentinel/web does not export getWebRoot(); serving placeholder dashboard');
    return undefined;
  }
  let root: string;
  try {
    root = web.getWebRoot();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    logger.warn(`getWebRoot() threw (${message}); serving placeholder dashboard`);
    return undefined;
  }
  return checkRootDir(root, logger);
}

/**
 * Build a static file server for the dashboard. The web root is resolved once at
 * startup. Requests are served only from within that root — a resolved path that
 * escapes it (traversal) is refused — and `/` falls back to the placeholder when
 * no root or index is available.
 */
export function createStaticServer(logger: ServerLogger, explicitRoot?: string): StaticServer {
  const webRoot =
    explicitRoot !== undefined ? checkRootDir(explicitRoot, logger) : resolveWebRoot(logger);

  function servePlaceholder(res: ServerResponse): void {
    sendText(res, 200, PLACEHOLDER_HTML, 'text/html; charset=utf-8');
  }

  return {
    serve(res: ServerResponse, pathname: string): void {
      if (webRoot === undefined) {
        if (pathname === '/') {
          servePlaceholder(res);
          return;
        }
        throw notFound();
      }

      let decoded: string;
      try {
        decoded = decodeURIComponent(pathname);
      } catch {
        throw notFound();
      }
      if (decoded.includes('\0')) throw notFound();

      const relative = decoded === '/' ? 'index.html' : decoded.replace(/^\/+/, '');
      const resolved = path.resolve(webRoot, relative);

      // Never serve files outside the web root.
      if (resolved !== webRoot && !resolved.startsWith(webRoot + path.sep)) {
        throw new HttpError(404, 'not_found', 'Not found');
      }

      let stat: ReturnType<typeof statSync>;
      try {
        stat = statSync(resolved);
      } catch {
        if (decoded === '/') {
          servePlaceholder(res);
          return;
        }
        throw notFound();
      }
      if (stat.isDirectory()) throw notFound();

      res.writeHead(200, {
        'Content-Type': contentTypeFor(resolved),
        'Content-Length': stat.size,
        'X-Content-Type-Options': 'nosniff',
      });
      const stream = createReadStream(resolved);
      stream.on('error', () => {
        if (!res.writableEnded) res.destroy();
      });
      stream.pipe(res);
    },
  };
}
