import { describe, expect, it } from 'vitest';
import { byRule, scanFixture } from './helpers.js';

describe('Kubernetes kind resolution', () => {
  it('resolves pod specs for Pod/Deployment/StatefulSet/DaemonSet/Job/CronJob and scans initContainers, skipping Service/ConfigMap without crashing', async () => {
    const findings = await scanFixture('kubernetes/kind-resolution/manifests.yaml');
    const i020 = byRule(findings, 'I020');
    expect(i020).toHaveLength(6);

    const i027 = byRule(findings, 'I027');
    expect(i027).toHaveLength(1);
    expect(i027[0]?.evidence).toContain('example/init');
  });
});

describe('I020 privileged security context', () => {
  it('flags securityContext.privileged: true', async () => {
    const findings = await scanFixture('kubernetes/init-containers/pod.yaml');
    const i020 = byRule(findings, 'I020');
    expect(i020).toHaveLength(1);
    expect(i020[0]).toMatchObject({
      severity: 'critical',
      confidence: 'high',
      category: 'infrastructure',
    });
  });
});

describe('I021 host namespace sharing', () => {
  it('flags hostNetwork, hostPID, and hostIPC independently', async () => {
    const findings = await scanFixture('kubernetes/host-namespaces/pod.yaml');
    const i021 = byRule(findings, 'I021');
    expect(i021).toHaveLength(3);
    const fields = i021.map((f) => f.metadata?.field).sort();
    expect(fields).toEqual(['hostIPC', 'hostNetwork', 'hostPID']);
    expect(i021.every((f) => f.severity === 'high' && f.confidence === 'high')).toBe(true);
  });
});

describe('I022 sensitive hostPath volume', () => {
  it('flags docker.sock (critical), root (high), and another path (medium)', async () => {
    const findings = await scanFixture('kubernetes/hostpath-volumes/pod.yaml');
    const i022 = byRule(findings, 'I022');
    expect(i022).toHaveLength(3);
    const bySeverity = Object.fromEntries(i022.map((f) => [f.metadata?.hostPath, f.severity]));
    expect(bySeverity['/var/run/docker.sock']).toBe('critical');
    expect(bySeverity['/']).toBe('high');
    expect(bySeverity['/opt/data']).toBe('medium');
  });
});

describe('I023 container may run as root', () => {
  it('flags a container with no runAsNonRoot and no runAsUser at either level', async () => {
    const findings = await scanFixture('kubernetes/run-as-root/pod.yaml');
    const i023 = byRule(findings, 'I023');
    expect(i023).toHaveLength(1);
    expect(i023[0]).toMatchObject({ severity: 'medium', confidence: 'medium' });
  });

  it('does not flag when runAsNonRoot is satisfied at the pod level or the container level', async () => {
    const findings = await scanFixture('kubernetes/run-as-nonroot/pod.yaml');
    expect(byRule(findings, 'I023')).toHaveLength(0);
  });
});

describe('I024 privilege escalation not blocked', () => {
  it('flags a container without allowPrivilegeEscalation: false', async () => {
    const findings = await scanFixture('kubernetes/privilege-escalation/pod.yaml');
    expect(byRule(findings, 'I024')).toHaveLength(1);
  });

  it('does not flag when allowPrivilegeEscalation is explicitly false', async () => {
    const findings = await scanFixture('kubernetes/privilege-escalation-blocked/pod.yaml');
    expect(findings).toHaveLength(0);
  });
});

describe('I025 added capabilities', () => {
  it('flags SYS_ADMIN (critical), NET_ADMIN (high), and NET_RAW (low)', async () => {
    const findings = await scanFixture('kubernetes/added-capabilities/pod.yaml');
    const i025 = byRule(findings, 'I025');
    expect(i025).toHaveLength(3);
    const byCap = Object.fromEntries(i025.map((f) => [f.metadata?.capability, f.severity]));
    expect(byCap.SYS_ADMIN).toBe('critical');
    expect(byCap.NET_ADMIN).toBe('high');
    expect(byCap.NET_RAW).toBe('low');
  });
});

describe('I026 no resource limits', () => {
  it('flags a container with no resources.limits', async () => {
    const findings = await scanFixture('kubernetes/no-resource-limits/pod.yaml');
    const i026 = byRule(findings, 'I026');
    expect(i026).toHaveLength(1);
    expect(i026[0]).toMatchObject({ severity: 'info', confidence: 'medium' });
  });

  it('does not flag a container with resources.limits set', async () => {
    const findings = await scanFixture('kubernetes/resource-limits/pod.yaml');
    expect(findings).toHaveLength(0);
  });
});

describe('I027 unpinned container image', () => {
  it('flags :latest and an untagged image', async () => {
    const findings = await scanFixture('kubernetes/unpinned-image/pod.yaml');
    expect(byRule(findings, 'I027')).toHaveLength(2);
  });

  it('does not flag a digest-pinned or tag-pinned image', async () => {
    const findings = await scanFixture('kubernetes/pinned-image/pod.yaml');
    expect(findings).toHaveLength(0);
  });
});

describe('I028 hardcoded secret in container env', () => {
  it('flags a literal secret value and redacts it', async () => {
    const findings = await scanFixture('kubernetes/env-secret/pod.yaml');
    const i028 = byRule(findings, 'I028');
    expect(i028).toHaveLength(1);
    expect(i028[0]).toMatchObject({ severity: 'high', confidence: 'medium' });
    const serialized = JSON.stringify(i028);
    expect(serialized).not.toContain('FAKEK8SSECRETEXAMPLE321');
    expect(serialized).toContain('[REDACTED]');
  });

  it('treats valueFrom.secretKeyRef as the negative case', async () => {
    const findings = await scanFixture('kubernetes/env-secret-ref/pod.yaml');
    expect(findings).toHaveLength(0);
  });
});

describe('Kubernetes clean manifest', () => {
  it('produces no findings when every safe pattern is used at once', async () => {
    const findings = await scanFixture('kubernetes/clean/deployment.yaml');
    expect(findings).toHaveLength(0);
  });
});
