import { describe, expect, it } from 'vitest';
import { dependenciesScanner } from '../../src/index.js';
import { contextFor, fileRef, fixturePath } from '../support.js';

function npmFile(name: string) {
  return fileRef(fixturePath('npm', 'well-formed', name), name);
}
function cargoFile(name: string) {
  return fileRef(fixturePath('cargo', 'well-formed', name), name);
}

describe('D003 manifest present without a lockfile', () => {
  it('fires for a package.json with dependencies when no lockfile is anywhere in the scanned set', async () => {
    const context = contextFor('/fake-root', [npmFile('package.json')], { config: {} });
    const findings = await dependenciesScanner.scan(context);
    const d003 = findings.filter((f) => f.ruleId === 'D003');
    expect(d003.length).toBe(1);
    expect(d003[0]?.file).toBe('package.json');
    expect(d003[0]?.severity).toBe('low');
    expect(d003[0]?.confidence).toBe('medium');
  });

  it('does not fire when package-lock.json is present alongside package.json', async () => {
    const context = contextFor(
      '/fake-root',
      [npmFile('package.json'), npmFile('package-lock.json')],
      {
        config: {},
      },
    );
    const findings = await dependenciesScanner.scan(context);
    expect(findings.some((f) => f.ruleId === 'D003')).toBe(false);
  });

  it('does not fire when yarn.lock (rather than package-lock.json) is present', async () => {
    const yarnLock = fileRef(fixturePath('rules', 'd003', 'yarn.lock'), 'yarn.lock');
    const context = contextFor('/fake-root', [npmFile('package.json'), yarnLock], { config: {} });
    const findings = await dependenciesScanner.scan(context);
    expect(findings.some((f) => f.ruleId === 'D003')).toBe(false);
  });

  it('does not fire for a package.json with no dependencies at all, lockfile or not', async () => {
    const ref = fileRef(fixturePath('npm', 'empty', 'package.json'), 'package.json');
    const context = contextFor('/fake-root', [ref], { config: {} });
    const findings = await dependenciesScanner.scan(context);
    expect(findings.some((f) => f.ruleId === 'D003')).toBe(false);
  });

  it('fires for a Cargo.toml when no Cargo.lock is anywhere in the scanned set', async () => {
    const context = contextFor('/fake-root', [cargoFile('Cargo.toml')], { config: {} });
    const findings = await dependenciesScanner.scan(context);
    const d003 = findings.filter((f) => f.ruleId === 'D003');
    expect(d003.length).toBe(1);
    expect(d003[0]?.file).toBe('Cargo.toml');
  });

  it('does not fire when Cargo.lock is present alongside Cargo.toml', async () => {
    const context = contextFor('/fake-root', [cargoFile('Cargo.toml'), cargoFile('Cargo.lock')], {
      config: {},
    });
    const findings = await dependenciesScanner.scan(context);
    expect(findings.some((f) => f.ruleId === 'D003')).toBe(false);
  });

  it('never fires for requirements.txt or go.mod, regardless of lockfile absence', async () => {
    const reqRef = fileRef(
      fixturePath('pip', 'well-formed', 'requirements.txt'),
      'requirements.txt',
    );
    const goRef = fileRef(fixturePath('go', 'well-formed', 'go.mod'), 'go.mod');
    const context = contextFor('/fake-root', [reqRef, goRef], { config: {} });
    const findings = await dependenciesScanner.scan(context);
    expect(findings.some((f) => f.ruleId === 'D003')).toBe(false);
  });

  it('fires independently of the dataSource setting (it is a hygiene check, not a vulnerability check)', async () => {
    const context = contextFor('/fake-root', [npmFile('package.json')], {
      config: { dataSource: 'file', advisoryDbPath: fixturePath('advisory-db', 'valid.json') },
    });
    const findings = await dependenciesScanner.scan(context);
    expect(findings.some((f) => f.ruleId === 'D003')).toBe(true);
  });
});
