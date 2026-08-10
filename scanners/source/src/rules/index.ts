import type { RuleModule } from './types.js';
import { c001CommandExec } from './c001-command-exec.js';
import { c002Eval } from './c002-eval.js';
import { c003SqlInjection } from './c003-sql-injection.js';
import { c004Deserialization } from './c004-deserialization.js';
import { c005PathTraversal } from './c005-path-traversal.js';
import { c006WeakHash } from './c006-weak-hash.js';
import { c007InsecureRandom } from './c007-insecure-random.js';
import { c008TlsVerification } from './c008-tls-verification.js';
import { c009Cors } from './c009-cors.js';
import { c010Chmod } from './c010-chmod.js';

// C011 ("hardcoded temp paths predictable") was scoped in the mission as
// optional ("include only if you can keep it quiet on clean-app; otherwise
// drop it"). It was deliberately dropped: a bare `/tmp/fixed-name` literal is
// extremely common in ordinary, non-vulnerable code (lock files, cache
// files, build scripts), and distinguishing a genuinely predictable/racy
// temp path from a benign one with a line-based heuristic would need either
// a wide, noisy pattern (most `/tmp/...` literals) or a narrow one that
// rarely fires -- neither clears this scanner's precision-over-recall bar.
// Ten precise rules beat eleven with one weak one.
export const rules: readonly RuleModule[] = [
  c001CommandExec,
  c002Eval,
  c003SqlInjection,
  c004Deserialization,
  c005PathTraversal,
  c006WeakHash,
  c007InsecureRandom,
  c008TlsVerification,
  c009Cors,
  c010Chmod,
];
