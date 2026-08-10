import { describe, expect, it } from 'vitest';
import { byRule, scanFixture } from './helpers.js';

describe('I030 security group ingress open to the internet', () => {
  it('flags an inline ingress block open to SSH as high', async () => {
    const findings = await scanFixture('terraform/ingress-inline-open-ssh/main.tf');
    const i030 = byRule(findings, 'I030');
    expect(i030).toHaveLength(1);
    expect(i030[0]).toMatchObject({
      severity: 'high',
      confidence: 'high',
      category: 'infrastructure',
    });
  });

  it('flags an inline all-ports/-1-protocol ingress block as high', async () => {
    const findings = await scanFixture('terraform/ingress-inline-all-ports/main.tf');
    expect(byRule(findings, 'I030')).toMatchObject([{ severity: 'high' }]);
  });

  it('flags an inline ordinary-port ingress block as medium', async () => {
    const findings = await scanFixture('terraform/ingress-inline-other-port/main.tf');
    expect(byRule(findings, 'I030')).toMatchObject([{ severity: 'medium' }]);
  });

  it('does not flag ingress restricted to a private CIDR', async () => {
    const findings = await scanFixture('terraform/ingress-inline-restricted/main.tf');
    expect(findings).toHaveLength(0);
  });

  it('flags a standalone aws_security_group_rule with type = "ingress"', async () => {
    const findings = await scanFixture('terraform/ingress-rule-resource/main.tf');
    expect(byRule(findings, 'I030')).toMatchObject([{ severity: 'high' }]);
  });

  it('does not flag an aws_security_group_rule with type = "egress"', async () => {
    const findings = await scanFixture('terraform/ingress-rule-egress-negative/main.tf');
    expect(findings).toHaveLength(0);
  });

  it('flags aws_vpc_security_group_ingress_rule (cidr_ipv4/ip_protocol attribute names)', async () => {
    const findings = await scanFixture('terraform/vpc-ingress-rule/main.tf');
    expect(byRule(findings, 'I030')).toMatchObject([{ severity: 'high' }]);
  });

  it('flags ipv6_cidr_blocks open to ::/0', async () => {
    const findings = await scanFixture('terraform/ipv6-open/main.tf');
    expect(byRule(findings, 'I030')).toMatchObject([{ severity: 'medium' }]);
  });
});

describe('I031 public S3 bucket ACL', () => {
  it('flags acl = "public-read-write" on aws_s3_bucket', async () => {
    const findings = await scanFixture('terraform/public-s3-acl/main.tf');
    const i031 = byRule(findings, 'I031');
    expect(i031).toHaveLength(1);
    expect(i031[0]).toMatchObject({ severity: 'high', confidence: 'high' });
  });

  it('flags acl = "public-read" on the standalone aws_s3_bucket_acl resource', async () => {
    const findings = await scanFixture('terraform/public-s3-acl-resource/main.tf');
    expect(byRule(findings, 'I031')).toHaveLength(1);
  });

  it('does not flag a private ACL', async () => {
    const findings = await scanFixture('terraform/private-s3-acl/main.tf');
    expect(findings).toHaveLength(0);
  });
});

describe('I032 hardcoded cloud credential', () => {
  it('flags literal access_key/secret_key on a provider and password on a resource, and redacts them', async () => {
    const findings = await scanFixture('terraform/hardcoded-credentials/main.tf');
    const i032 = byRule(findings, 'I032');
    expect(i032).toHaveLength(3);
    expect(i032.every((f) => f.severity === 'critical' && f.confidence === 'high')).toBe(true);
    const serialized = JSON.stringify(i032);
    expect(serialized).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(serialized).not.toContain('wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY');
    expect(serialized).not.toContain('FAKEDBPASSWORDEXAMPLE999');
    expect(serialized).toContain('[REDACTED]');
  });

  it('treats var. references (bare and interpolated) as the negative case', async () => {
    const findings = await scanFixture('terraform/credentials-var-reference/main.tf');
    expect(findings).toHaveLength(0);
  });
});

describe('I033 encryption explicitly disabled', () => {
  it('flags storage_encrypted = false, encrypted = false, and server_side_encryption { enabled = false }', async () => {
    const findings = await scanFixture('terraform/encryption-disabled/main.tf');
    expect(byRule(findings, 'I033')).toHaveLength(3);
  });

  it('does not flag encryption explicitly enabled, or simply absent', async () => {
    const findings = await scanFixture('terraform/encryption-not-disabled/main.tf');
    expect(findings).toHaveLength(0);
  });
});

describe('Terraform clean file', () => {
  it('produces no findings when every safe pattern is used at once', async () => {
    const findings = await scanFixture('terraform/clean/main.tf');
    expect(findings).toHaveLength(0);
  });
});
