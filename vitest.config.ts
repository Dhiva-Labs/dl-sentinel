import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

function src(rel: string): string {
  return fileURLToPath(new URL(rel, import.meta.url));
}

export default defineConfig({
  resolve: {
    alias: {
      '@dl-sentinel/core': src('./packages/core/src/index.ts'),
      '@dl-sentinel/engine': src('./packages/engine/src/index.ts'),
      '@dl-sentinel/reporting': src('./packages/reporting/src/index.ts'),
      '@dl-sentinel/scanner-secrets': src('./scanners/secrets/src/index.ts'),
      '@dl-sentinel/scanner-dependencies': src('./scanners/dependencies/src/index.ts'),
      '@dl-sentinel/scanner-source': src('./scanners/source/src/index.ts'),
      '@dl-sentinel/scanner-infra': src('./scanners/infra/src/index.ts'),
      '@dl-sentinel/scanner-api': src('./scanners/api/src/index.ts'),
      '@dl-sentinel/scanner-smart-contract': src('./scanners/smart-contract/src/index.ts'),
      '@dl-sentinel/cli': src('./apps/cli/src/index.ts'),
      '@dl-sentinel/api-server': src('./apps/api/src/index.ts'),
      '@dl-sentinel/web': src('./apps/web/src/index.ts'),
    },
  },
  test: {
    include: [
      'packages/*/test/**/*.test.ts',
      'scanners/*/test/**/*.test.ts',
      'apps/*/test/**/*.test.ts',
      'tests/**/*.test.ts',
    ],
    passWithNoTests: true,
    testTimeout: 20000,
    hookTimeout: 20000,
  },
});
