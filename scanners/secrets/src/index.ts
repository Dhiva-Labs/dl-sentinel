/**
 * DL Sentinel secrets scanner.
 *
 * Detects credentials committed to a repository — vendor token formats, PEM
 * private keys, credential-bearing URLs, and credential-named assignments —
 * under one hard invariant: a raw secret value never appears in a Finding, a
 * log line, or an error. See src/scan.ts for how that is enforced and
 * src/placeholders.ts for the placeholder policy (including why a format-valid
 * `AKIA…EXAMPLE` key is still a finding).
 *
 * Contract: docs/scanner-interface.md. The plugin is this module's default
 * export; `secretsScanner` is the same object under a name, for tests.
 */

import type { Finding, ScanContext, ScannerPlugin } from '@dl-sentinel/core';
import { rules } from './rules.js';
import { SCANNER_ID, scanForSecrets } from './scan.js';

export const secretsScanner: ScannerPlugin = {
  id: SCANNER_ID,
  name: 'Secrets Scanner',
  version: '0.1.0',
  categories: ['secrets'],
  // Secrets turn up in any text file, so take everything the engine offers.
  supportedFiles: [],
  rules,
  scan(context: ScanContext): Promise<Finding[]> {
    return scanForSecrets(context);
  },
};

export { rules as secretsRules, RULE_IDS } from './rules.js';
export type { SecretsConfig } from './config.js';

export default secretsScanner;
