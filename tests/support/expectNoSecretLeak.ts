import { expect } from 'vitest';
import type { Finding } from '@dl-sentinel/core';

/**
 * Assert that none of `plantedValues` appear anywhere in the serialized
 * findings — the same check docs/finding-schema.md requires of every
 * secret-producing rule ("assert JSON.stringify(findings) does not contain
 * the planted fixture value").
 */
export function expectNoSecretLeak(
  findings: readonly Finding[],
  plantedValues: readonly string[],
): void {
  const serialized = JSON.stringify(findings);
  for (const value of plantedValues) {
    expect(serialized, `planted secret leaked into findings: ${value}`).not.toContain(value);
  }
}
