import type { Finding, Severity } from '@dl-sentinel/core';
import { ruleDef } from '../rules-meta.js';
import { buildFinding } from '../util/build-finding.js';
import { buildLineStarts, lineForOffset, splitLines } from '../util/text-lines.js';
import {
  attributeMap,
  classifyChars,
  findTopLevelBlocks,
  isReferenceExpression,
  parseBoolLiteral,
  parseNumber,
  parseStringList,
  scanBody,
  unquote,
  type TfAttribute,
  type TfBlock,
} from './parse.js';

const SENSITIVE_PORTS = [22, 3389];
const CREDENTIAL_ATTR_NAMES = ['access_key', 'secret_key', 'password'];

interface TfCtx {
  text: string;
  cls: Uint8Array;
  lineStarts: number[];
  lines: string[];
  file: string;
}

function evidenceAtOffset(
  ctx: TfCtx,
  offset: number,
  fallback: string,
): { line: number; evidence: string } {
  const line = lineForOffset(ctx.lineStarts, offset);
  const text = ctx.lines[line - 1]?.trim();
  return { line, evidence: text && text.length > 0 ? text : fallback };
}

function blockLabel(block: TfBlock): string {
  return block.kind === 'provider' ? `provider "${block.type}"` : `${block.type}.${block.name}`;
}

interface IngressEvaluation {
  allPorts: boolean;
  sensitivePort: boolean;
}

/** Evaluate a set of ingress-shaped attributes (works for the inline `ingress {}` block of
 * aws_security_group, the flat body of aws_security_group_rule, and the flat body of
 * aws_vpc_security_group_ingress_rule — they use different attribute names for the same
 * concepts, which this function normalizes). Returns undefined when the rule isn't open to
 * the world at all. */
function evaluateIngress(attrs: Map<string, TfAttribute>): IngressEvaluation | undefined {
  let open = false;

  const cidrBlocks = attrs.get('cidr_blocks');
  if (cidrBlocks && parseStringList(cidrBlocks.raw).includes('0.0.0.0/0')) open = true;

  const cidrIpv4 = attrs.get('cidr_ipv4');
  if (cidrIpv4 && unquote(cidrIpv4.raw) === '0.0.0.0/0') open = true;

  const ipv6CidrBlocks = attrs.get('ipv6_cidr_blocks');
  if (ipv6CidrBlocks && parseStringList(ipv6CidrBlocks.raw).includes('::/0')) open = true;

  const cidrIpv6 = attrs.get('cidr_ipv6');
  if (cidrIpv6 && unquote(cidrIpv6.raw) === '::/0') open = true;

  if (!open) return undefined;

  const fromPort = parseNumber(attrs.get('from_port')?.raw);
  const toPort = parseNumber(attrs.get('to_port')?.raw);
  const protocolAttr = attrs.get('protocol') ?? attrs.get('ip_protocol');
  const protocol = protocolAttr ? unquote(protocolAttr.raw) : undefined;

  const allPorts =
    protocol === '-1' ||
    (fromPort === 0 && toPort === 0) ||
    (fromPort !== undefined && toPort !== undefined && fromPort <= 0 && toPort >= 65535);

  const sensitivePort = SENSITIVE_PORTS.some((port) => {
    if (fromPort !== undefined && toPort !== undefined) return fromPort <= port && toPort >= port;
    return fromPort === port || toPort === port;
  });

  return { allPorts, sensitivePort };
}

function severityForIngress(evaluation: IngressEvaluation): Severity {
  return evaluation.allPorts || evaluation.sensitivePort ? 'high' : 'medium';
}

function emitIngressFinding(
  ctx: TfCtx,
  offset: number,
  label: string,
  severity: Severity,
): Finding {
  const def = ruleDef('I030');
  const { line, evidence } = evidenceAtOffset(
    ctx,
    offset,
    `${label}: ingress open to the internet`,
  );
  return buildFinding({
    ruleId: def.id,
    title: def.title,
    description: def.description,
    recommendation: def.recommendation,
    references: def.references,
    category: def.category,
    severity,
    confidence: 'high',
    file: ctx.file,
    line,
    evidence,
  });
}

/** aws_security_group: inline `ingress { ... }` nested blocks. */
function checkInlineIngress(ctx: TfCtx, block: TfBlock): Finding[] {
  if (block.type !== 'aws_security_group') return [];
  const { nested } = scanBody(ctx.text, ctx.cls, block.bodyStart, block.bodyEnd);
  const findings: Finding[] = [];
  for (const nb of nested) {
    if (nb.name !== 'ingress') continue;
    const { attributes } = scanBody(ctx.text, ctx.cls, nb.bodyStart, nb.bodyEnd);
    const evaluation = evaluateIngress(attributeMap(attributes));
    if (!evaluation) continue;
    findings.push(
      emitIngressFinding(
        ctx,
        nb.declOffset,
        `${blockLabel(block)}.ingress`,
        severityForIngress(evaluation),
      ),
    );
  }
  return findings;
}

/** aws_security_group_rule: a standalone rule resource, ingress only when type = "ingress". */
function checkSecurityGroupRuleResource(ctx: TfCtx, block: TfBlock): Finding[] {
  if (block.type !== 'aws_security_group_rule') return [];
  const { attributes } = scanBody(ctx.text, ctx.cls, block.bodyStart, block.bodyEnd);
  const map = attributeMap(attributes);
  const typeAttr = map.get('type');
  if (!typeAttr || unquote(typeAttr.raw) !== 'ingress') return [];
  const evaluation = evaluateIngress(map);
  if (!evaluation) return [];
  return [
    emitIngressFinding(ctx, block.declOffset, blockLabel(block), severityForIngress(evaluation)),
  ];
}

/** aws_vpc_security_group_ingress_rule: newer AWS-provider resource, inherently ingress-only. */
function checkVpcIngressRuleResource(ctx: TfCtx, block: TfBlock): Finding[] {
  if (block.type !== 'aws_vpc_security_group_ingress_rule') return [];
  const { attributes } = scanBody(ctx.text, ctx.cls, block.bodyStart, block.bodyEnd);
  const evaluation = evaluateIngress(attributeMap(attributes));
  if (!evaluation) return [];
  return [
    emitIngressFinding(ctx, block.declOffset, blockLabel(block), severityForIngress(evaluation)),
  ];
}

/** I031: public canned ACL on an S3 bucket (inline `acl =` or the standalone *_acl resource). */
function checkPublicBucketAcl(ctx: TfCtx, block: TfBlock): Finding[] {
  if (block.kind !== 'resource') return [];
  if (block.type !== 'aws_s3_bucket' && block.type !== 'aws_s3_bucket_acl') return [];
  const { attributes } = scanBody(ctx.text, ctx.cls, block.bodyStart, block.bodyEnd);
  const aclAttr = attributeMap(attributes).get('acl');
  if (!aclAttr) return [];
  const acl = unquote(aclAttr.raw);
  if (acl !== 'public-read' && acl !== 'public-read-write') return [];

  const def = ruleDef('I031');
  const { line, evidence } = evidenceAtOffset(
    ctx,
    aclAttr.offset,
    `${blockLabel(block)}.acl = "${acl}"`,
  );
  return [
    buildFinding({
      ruleId: def.id,
      title: def.title,
      description: def.description,
      recommendation: def.recommendation,
      references: def.references,
      category: def.category,
      severity: def.severity,
      confidence: def.defaultConfidence,
      file: ctx.file,
      line,
      evidence,
    }),
  ];
}

/**
 * I032: hardcoded access_key/secret_key/password on any resource or
 * provider block. A `var.`/`data.`/`local.`/`module.` reference (quoted
 * interpolation or bare) is the documented negative case; anything else
 * that resolves to a non-empty literal string is flagged.
 */
function checkHardcodedCredentials(ctx: TfCtx, block: TfBlock): Finding[] {
  const { attributes } = scanBody(ctx.text, ctx.cls, block.bodyStart, block.bodyEnd);
  const def = ruleDef('I032');
  const findings: Finding[] = [];
  for (const attr of attributes) {
    if (!CREDENTIAL_ATTR_NAMES.includes(attr.key)) continue;
    if (isReferenceExpression(attr.raw)) continue;
    const value = unquote(attr.raw);
    if (value === undefined || value.trim().length === 0) continue;

    const { line, evidence } = evidenceAtOffset(
      ctx,
      attr.offset,
      `${blockLabel(block)}.${attr.key} = "${value}"`,
    );
    findings.push(
      buildFinding({
        ruleId: def.id,
        title: def.title,
        description: def.description,
        recommendation: def.recommendation,
        references: def.references,
        category: def.category,
        severity: def.severity,
        confidence: def.defaultConfidence,
        file: ctx.file,
        line,
        evidence,
        secrets: [value],
      }),
    );
  }
  return findings;
}

/**
 * I033: encryption explicitly disabled. Only `encrypted`/`storage_encrypted`
 * set to the literal `false`, or a nested `server_side_encryption { enabled
 * = false }` block, are checked — absence of an encryption attribute is
 * never flagged (defaults vary by resource and provider version).
 */
function checkEncryptionDisabled(ctx: TfCtx, block: TfBlock): Finding[] {
  if (block.kind !== 'resource') return [];
  const def = ruleDef('I033');
  const findings: Finding[] = [];
  const { attributes, nested } = scanBody(ctx.text, ctx.cls, block.bodyStart, block.bodyEnd);
  const map = attributeMap(attributes);

  for (const key of ['encrypted', 'storage_encrypted']) {
    const attr = map.get(key);
    if (!attr || parseBoolLiteral(attr.raw) !== false) continue;
    const { line, evidence } = evidenceAtOffset(
      ctx,
      attr.offset,
      `${blockLabel(block)}.${key} = false`,
    );
    findings.push(
      buildFinding({
        ruleId: def.id,
        title: def.title,
        description: def.description,
        recommendation: def.recommendation,
        references: def.references,
        category: def.category,
        severity: def.severity,
        confidence: def.defaultConfidence,
        file: ctx.file,
        line,
        evidence,
      }),
    );
  }

  for (const nb of nested) {
    if (nb.name !== 'server_side_encryption') continue;
    const { attributes: sseAttrs } = scanBody(ctx.text, ctx.cls, nb.bodyStart, nb.bodyEnd);
    const enabledAttr = attributeMap(sseAttrs).get('enabled');
    if (!enabledAttr || parseBoolLiteral(enabledAttr.raw) !== false) continue;
    const { line, evidence } = evidenceAtOffset(
      ctx,
      enabledAttr.offset,
      `${blockLabel(block)}.server_side_encryption.enabled = false`,
    );
    findings.push(
      buildFinding({
        ruleId: def.id,
        title: def.title,
        description: def.description,
        recommendation: def.recommendation,
        references: def.references,
        category: def.category,
        severity: def.severity,
        confidence: def.defaultConfidence,
        file: ctx.file,
        line,
        evidence,
      }),
    );
  }

  return findings;
}

export function scanTerraform(text: string, file: string): Finding[] {
  const cls = classifyChars(text);
  const ctx: TfCtx = {
    text,
    cls,
    lineStarts: buildLineStarts(text),
    lines: splitLines(text),
    file,
  };

  const findings: Finding[] = [];
  for (const block of findTopLevelBlocks(text, cls)) {
    findings.push(...checkInlineIngress(ctx, block));
    findings.push(...checkSecurityGroupRuleResource(ctx, block));
    findings.push(...checkVpcIngressRuleResource(ctx, block));
    findings.push(...checkPublicBucketAcl(ctx, block));
    findings.push(...checkHardcodedCredentials(ctx, block));
    findings.push(...checkEncryptionDisabled(ctx, block));
  }
  return findings;
}
