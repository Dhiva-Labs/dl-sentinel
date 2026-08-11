/**
 * The correlation catalog: every chain the analyzer knows how to propose.
 *
 * This array is the whole of the feature's knowledge. A combination that is not
 * declared here is not reported, and every declared rule states in its
 * `conditions` (and its module JSDoc) exactly which findings must co-occur —
 * mirrored in the catalog table in docs/attack-paths.md.
 */
import type { CorrelationRule } from './types.js';
import { AP001 } from './rules/ap001-privileged-exposure.js';
import { AP002 } from './rules/ap002-credential-reachable-service.js';
import { AP003 } from './rules/ap003-vulnerable-dependency-exposed.js';
import { AP004 } from './rules/ap004-cloud-storage-exposure.js';
import { AP005 } from './rules/ap005-unauthenticated-cleartext.js';
import { AP006 } from './rules/ap006-injection-api-surface.js';
import { AP007 } from './rules/ap007-container-secret-host-mount.js';

export const CORRELATION_RULES: readonly CorrelationRule[] = [
  AP001,
  AP002,
  AP003,
  AP004,
  AP005,
  AP006,
  AP007,
];

export { AP001, AP002, AP003, AP004, AP005, AP006, AP007 };
