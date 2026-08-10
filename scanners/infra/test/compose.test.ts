import { describe, expect, it } from 'vitest';
import { byRule, scanFixture } from './helpers.js';

describe('I010 privileged container', () => {
  it('flags privileged: true', async () => {
    const findings = await scanFixture('compose/privileged/docker-compose.yml');
    const i010 = byRule(findings, 'I010');
    expect(i010).toHaveLength(1);
    expect(i010[0]).toMatchObject({ severity: 'critical', confidence: 'high', category: 'docker' });
  });

  it('does not flag a service without privileged', async () => {
    const findings = await scanFixture('compose/not-privileged/docker-compose.yml');
    expect(findings).toHaveLength(0);
  });
});

describe('I011 host network mode', () => {
  it('flags network_mode: host', async () => {
    const findings = await scanFixture('compose/host-network/docker-compose.yml');
    const i011 = byRule(findings, 'I011');
    expect(i011).toHaveLength(1);
    expect(i011[0]).toMatchObject({ severity: 'high', confidence: 'high' });
  });

  it('does not flag the default bridge network', async () => {
    const findings = await scanFixture('compose/bridge-network/docker-compose.yml');
    expect(findings).toHaveLength(0);
  });
});

describe('I012 sensitive host path mounted', () => {
  it('flags docker.sock (critical), / and /etc (high), other paths (medium) — short syntax', async () => {
    const findings = await scanFixture('compose/host-mounts/docker-compose.yml');
    const i012 = byRule(findings, 'I012');
    expect(i012).toHaveLength(4);
    const bySeverity = Object.fromEntries(i012.map((f) => [f.metadata?.hostPath, f.severity]));
    expect(bySeverity['/var/run/docker.sock']).toBe('critical');
    expect(bySeverity['/']).toBe('high');
    expect(bySeverity['/etc']).toBe('high');
    expect(bySeverity['/home/user/data']).toBe('medium');
    const dockerSockFinding = i012.find((f) => f.metadata?.hostPath === '/var/run/docker.sock');
    expect(dockerSockFinding?.metadata?.dockerSocket).toBe(true);
  });

  it('flags bind mounts using the long volume syntax', async () => {
    const findings = await scanFixture('compose/host-mounts-long-syntax/docker-compose.yml');
    const i012 = byRule(findings, 'I012');
    expect(i012).toHaveLength(2);
    const bySeverity = Object.fromEntries(i012.map((f) => [f.metadata?.hostPath, f.severity]));
    expect(bySeverity['/etc']).toBe('high');
    expect(bySeverity['/opt/data']).toBe('medium');
  });

  it('does not flag named volumes (short or long syntax) or anonymous container-only paths', async () => {
    const findings = await scanFixture('compose/named-volumes/docker-compose.yml');
    expect(findings).toHaveLength(0);
  });
});

describe('I013 dangerous cap_add', () => {
  it('flags SYS_ADMIN (critical) and NET_ADMIN (high), not NET_RAW', async () => {
    const findings = await scanFixture('compose/cap-add/docker-compose.yml');
    const i013 = byRule(findings, 'I013');
    expect(i013).toHaveLength(2);
    const byCap = Object.fromEntries(i013.map((f) => [f.metadata?.capability, f.severity]));
    expect(byCap.SYS_ADMIN).toBe('critical');
    expect(byCap.NET_ADMIN).toBe('high');
    expect(byCap.NET_RAW).toBeUndefined();
  });

  it('does not flag capabilities outside the dangerous set', async () => {
    const findings = await scanFixture('compose/cap-add-safe/docker-compose.yml');
    expect(findings).toHaveLength(0);
  });
});

describe('I014 hardcoded secret in environment', () => {
  it('flags literal secrets in both map-form and list-form environment, and redacts them', async () => {
    const findings = await scanFixture('compose/env-secrets/docker-compose.yml');
    const i014 = byRule(findings, 'I014');
    expect(i014).toHaveLength(2);
    expect(i014.every((f) => f.severity === 'high' && f.confidence === 'medium')).toBe(true);
    const serialized = JSON.stringify(i014);
    expect(serialized).not.toContain('FAKESECRETEXAMPLE456');
    expect(serialized).not.toContain('FAKETOKENEXAMPLE789');
    expect(serialized).toContain('[REDACTED]');
  });

  it('does not flag interpolation references, placeholders, or passthrough vars', async () => {
    const findings = await scanFixture('compose/env-safe/docker-compose.yml');
    expect(findings).toHaveLength(0);
  });
});

describe('I015 no resource limits', () => {
  it('flags only the service without deploy.resources.limits', async () => {
    const findings = await scanFixture('compose/resource-limits/docker-compose.yml');
    const i015 = byRule(findings, 'I015');
    expect(i015).toHaveLength(1);
    expect(i015[0]).toMatchObject({ severity: 'info', confidence: 'medium' });
    expect(i015[0]?.metadata?.service).toBe('unlimited');
  });
});

describe('I016 database port published without host IP restriction', () => {
  it('flags unrestricted db ports but not an ordinary app port', async () => {
    const findings = await scanFixture('compose/db-ports/docker-compose.yml');
    const i016 = byRule(findings, 'I016');
    expect(i016).toHaveLength(2);
    expect(i016.every((f) => f.severity === 'medium' && f.confidence === 'medium')).toBe(true);
  });

  it('does not flag a db port bound to a specific host IP', async () => {
    const findings = await scanFixture('compose/db-ports-restricted/docker-compose.yml');
    expect(findings).toHaveLength(0);
  });
});
