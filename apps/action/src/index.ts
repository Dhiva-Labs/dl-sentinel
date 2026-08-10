// DL Sentinel GitHub Action. Implemented on feature/sentinel-pr-scanning.
// Scans a checked-out repository, compares against a base baseline so only
// findings introduced by a pull request are reported, and surfaces them via a
// PR comment and/or a SARIF upload. Pure Node (no @actions/* dependency).
export {};
