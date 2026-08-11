import { describe, expect, it } from 'vitest';
import { sc014UnprotectedUpgrade } from '../../src/rules/sc014-unprotected-upgrade.js';
import { parseFixture } from '../helpers.js';

function evaluate(relPath: string) {
  return sc014UnprotectedUpgrade.evaluate({ relPath, file: parseFixture(relPath) });
}

describe('SC014 unprotected upgrade function', () => {
  const findings = evaluate('sc014-positive.sol');

  it('fires on an empty _authorizeUpgrade hook (the classic UUPS bug)', () => {
    const hook = findings.find((f) => f.metadata?.kind === 'authorize-hook')!;
    expect(hook).toMatchObject({
      ruleId: 'SC014',
      severity: 'high',
      confidence: 'medium',
      line: 11,
    });
    expect(hook.metadata).toMatchObject({ function: '_authorizeUpgrade' });
  });

  it('fires on an unguarded external upgradeTo', () => {
    const entry = findings.find((f) => f.metadata?.kind === 'upgrade-entry')!;
    expect(entry).toMatchObject({ ruleId: 'SC014', line: 22 });
    expect(entry.metadata).toMatchObject({ function: 'upgradeTo' });
  });

  it('reports each shape exactly once', () => {
    expect(findings).toHaveLength(2);
  });

  it('does not fire when the hook carries a modifier that really checks the caller', () => {
    expect(evaluate('sc014-negative.sol')).toHaveLength(0);
  });

  it('does not fire on unrelated functions that merely mention upgrades', () => {
    expect(evaluate('sc001-positive.sol')).toHaveLength(0);
  });
});
