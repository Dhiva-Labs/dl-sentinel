// DL Sentinel GitHub Action. Implemented on feature/sentinel-pr-scanning.
// Scans a checked-out repository, compares against a base baseline so only
// findings introduced by a pull request are reported, and surfaces them via a
// PR comment and/or a SARIF upload. Pure Node (no @actions/* dependency).
//
// This barrel exports the testable surface; main.ts is the executable entry.
export { runAction } from './action.js';
export { EXIT, type ExitCode } from './exit-codes.js';
export {
  parseInputs,
  parseBool,
  parseSeverityList,
  resolveToken,
  type ActionInputs,
} from './inputs.js';
export { readPullRequestContext, type PullRequestContext } from './event.js';
export {
  scanTarget,
  diffAgainstBaseline,
  readBaselineFile,
  baselineFromBase,
  type ScanRequest,
  type NewFindingsResult,
} from './scan.js';
export { buildSummary, COMMENT_MARKER, type SummaryInput } from './summary.js';
export {
  upsertStickyComment,
  type CommentTarget,
  type CommentResult,
  type CommentAction,
} from './github.js';
export { notice, warning, error, writeOutputs, appendStepSummary } from './workflow.js';
export type { ActionIO, FetchLike, FetchInitLike, FetchResponseLike } from './io.js';
