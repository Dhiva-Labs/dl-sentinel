/**
 * Default engine preset: the set of built-in scanners and a factory that
 * returns an engine with all of them registered. Every app (CLI, API server)
 * should build its engine through here so the scanner roster stays consistent
 * and is defined in exactly one place.
 */

import type { ScannerPlugin } from '@dl-sentinel/core';
import { createEngine, type ScanEngine } from '@dl-sentinel/engine';
import apiScanner from '@dl-sentinel/scanner-api';
import dependenciesScanner from '@dl-sentinel/scanner-dependencies';
import infraScanner from '@dl-sentinel/scanner-infra';
import secretsScanner from '@dl-sentinel/scanner-secrets';
import smartContractScanner from '@dl-sentinel/scanner-smart-contract';
import sourceScanner from '@dl-sentinel/scanner-source';

/**
 * The built-in scanners, in a stable, presentation-friendly order (secrets and
 * dependencies first, definition/contract scanners last). This order is what
 * `sentinel rules` and the dashboard's rule list render in.
 */
export const BUILTIN_SCANNERS: readonly ScannerPlugin[] = Object.freeze([
  secretsScanner,
  dependenciesScanner,
  sourceScanner,
  infraScanner,
  apiScanner,
  smartContractScanner,
]);

/** Create a scan engine with every built-in scanner registered. */
export function createDefaultEngine(): ScanEngine {
  const engine = createEngine();
  for (const scanner of BUILTIN_SCANNERS) {
    engine.register(scanner);
  }
  return engine;
}
