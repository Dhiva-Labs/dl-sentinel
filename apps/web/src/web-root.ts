import { existsSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

/**
 * Absolute path to the dashboard's static asset directory (`apps/web/public`
 * in this repo; ships as `public/` inside the published package — see the
 * `files` field in package.json).
 *
 * Resolution: `public/` is a sibling of `dist/` at the package root
 * (`apps/web/{dist,public}`). This module compiles to `dist/web-root.js`,
 * so `new URL('../public', import.meta.url)` walks from that compiled
 * file's own directory (`dist/`) up to the package root and back down into
 * `public/`. That makes the result correct regardless of the caller's
 * `process.cwd()` or how the package was installed/hoisted — it is derived
 * from this module's own location on disk, not from ambient state.
 *
 * The directory (and an `index.html` inside it) are verified to exist so a
 * broken package (e.g. `public/` not shipped, or `npm run build` not run)
 * fails loudly at the call site instead of the API server silently 404ing
 * every asset request.
 */
export function getWebRoot(): string {
  const root = fileURLToPath(new URL('../public', import.meta.url));

  if (!existsSync(root) || !statSync(root).isDirectory()) {
    throw new Error(
      `@dl-sentinel/web: static asset directory not found at ${root}. ` +
        'Expected "public" to ship as a sibling of "dist" (see apps/web/package.json ' +
        '"files"). If you are developing locally, run "npm run build" first.',
    );
  }

  const indexHtml = join(root, 'index.html');
  if (!existsSync(indexHtml)) {
    throw new Error(`@dl-sentinel/web: static asset directory at ${root} is missing index.html.`);
  }

  return root;
}
