import type { Category, Confidence, RuleMeta, Severity } from '@dl-sentinel/core';

/**
 * Single source of truth for rule metadata: id, nominal severity/confidence
 * (the `sentinel rules` listing value — individual findings from multi-tier
 * rules choose the actual severity/confidence per match, which may differ),
 * category, human copy, and references. Rule modules pull title/description/
 * recommendation/category/references from here when building findings so
 * the declared metadata and the emitted findings never drift apart.
 */
export interface RuleDef {
  id: string;
  title: string;
  severity: Severity;
  defaultConfidence: Confidence;
  category: Category;
  description: string;
  recommendation: string;
  references: string[];
}

const DOCKER_REFS = ['https://docs.docker.com/engine/reference/builder/'];
const COMPOSE_REFS = ['https://docs.docker.com/compose/compose-file/'];
const K8S_REFS = ['https://kubernetes.io/docs/concepts/security/pod-security-standards/'];
const TF_REFS = ['https://developer.hashicorp.com/terraform/language'];

export const RULE_DEFS: readonly RuleDef[] = [
  // ---- Dockerfile (I00x) ----
  {
    id: 'I001',
    title: 'Container runs as root',
    severity: 'high',
    defaultConfidence: 'high',
    category: 'docker',
    description:
      'The image has no USER instruction in its final stage, or the last USER instruction ' +
      'switches back to root (root/0), so the container runs its process as root by default.',
    recommendation:
      'Add a non-root USER instruction (with a matching unprivileged user created in the ' +
      'image) as the last user-switching instruction of the final build stage.',
    references: DOCKER_REFS,
  },
  {
    id: 'I002',
    title: 'ADD instruction fetches a remote URL',
    severity: 'medium',
    defaultConfidence: 'high',
    category: 'docker',
    description:
      'ADD with an http:// or https:// source downloads a remote file at build time with no ' +
      'integrity verification and no build cache invalidation control.',
    recommendation:
      'Use COPY for local content, or download with a pinned checksum verification step ' +
      '(e.g. curl + sha256sum check) inside a RUN instruction instead of ADD <url>.',
    references: DOCKER_REFS,
  },
  {
    id: 'I003',
    title: 'Unpinned base image',
    severity: 'medium',
    defaultConfidence: 'high',
    category: 'docker',
    description:
      'The FROM instruction has no tag (implicit :latest), an explicit :latest tag, or no ' +
      'digest, so the exact base image contents can change between builds.',
    recommendation: 'Pin the base image to an explicit version tag or, better, a @sha256 digest.',
    references: DOCKER_REFS,
  },
  {
    id: 'I004',
    title: 'Hardcoded secret in ENV/ARG',
    severity: 'critical',
    defaultConfidence: 'medium',
    category: 'docker',
    description:
      'An ENV or ARG instruction assigns a literal, non-placeholder value to a variable whose ' +
      'name looks like a credential (password/secret/token/api key/credential); the value is ' +
      'baked into image layers and metadata.',
    recommendation:
      'Remove the literal value. Pass secrets at runtime (env, mounted file, or a secret ' +
      'manager) rather than baking them into the image.',
    references: DOCKER_REFS,
  },
  {
    id: 'I005',
    title: 'Piped remote script execution',
    severity: 'medium',
    defaultConfidence: 'high',
    category: 'docker',
    description:
      'A RUN instruction pipes curl/wget output directly into a shell, executing unverified ' +
      'remote content with no integrity check.',
    recommendation:
      'Download the script, verify its checksum or signature, then execute it, instead of ' +
      'piping curl/wget straight into sh/bash.',
    references: DOCKER_REFS,
  },
  {
    id: 'I006',
    title: 'Administrative port exposed',
    severity: 'low',
    defaultConfidence: 'medium',
    category: 'docker',
    description:
      'EXPOSE declares a well-known administrative port (SSH 22/23 or the unauthenticated ' +
      'Docker API port 2375), inviting it to be published on containers run with -P.',
    recommendation:
      'Do not expose administrative/management ports from application images; if remote ' +
      'access is required, use a dedicated, authenticated channel instead.',
    references: DOCKER_REFS,
  },

  // ---- Compose (I01x) ----
  {
    id: 'I010',
    title: 'Privileged container',
    severity: 'critical',
    defaultConfidence: 'high',
    category: 'docker',
    description:
      'The service sets privileged: true, disabling nearly all container isolation and ' +
      'granting the container full access to host devices.',
    recommendation: 'Remove privileged: true; grant only the specific capabilities required.',
    references: COMPOSE_REFS,
  },
  {
    id: 'I011',
    title: 'Host network mode',
    severity: 'high',
    defaultConfidence: 'high',
    category: 'docker',
    description:
      'The service sets network_mode: host, removing network namespace isolation between the ' +
      'container and the host.',
    recommendation:
      'Use the default bridge network (or a user-defined network) and publish only the ports ' +
      'the service needs.',
    references: COMPOSE_REFS,
  },
  {
    id: 'I012',
    title: 'Sensitive host path mounted',
    severity: 'critical',
    defaultConfidence: 'high',
    category: 'docker',
    description:
      'The service bind-mounts a sensitive host path into the container: the Docker socket ' +
      '(full host/daemon control), the host root or /etc (whole-filesystem access), or another ' +
      'host directory outside of a named volume.',
    recommendation:
      'Avoid mounting the Docker socket or host system directories; use named volumes or the ' +
      'narrowest possible host path instead.',
    references: COMPOSE_REFS,
  },
  {
    id: 'I013',
    title: 'Dangerous Linux capability added',
    severity: 'critical',
    defaultConfidence: 'high',
    category: 'docker',
    description:
      'The service adds a Linux capability (via cap_add) known to enable container breakout ' +
      'or host tampering: SYS_ADMIN/ALL (critical) or NET_ADMIN/SYS_PTRACE (high).',
    recommendation:
      'Drop ALL capabilities by default and add back only the specific, narrow capability the ' +
      'service actually needs.',
    references: COMPOSE_REFS,
  },
  {
    id: 'I014',
    title: 'Hardcoded secret in environment',
    severity: 'high',
    defaultConfidence: 'medium',
    category: 'docker',
    description:
      'A service environment entry assigns a literal, non-placeholder value to a variable ' +
      'whose name looks like a credential.',
    recommendation:
      'Use an env_file, secrets:, or an external secret manager instead of a literal value in ' +
      'the compose file.',
    references: COMPOSE_REFS,
  },
  {
    id: 'I015',
    title: 'No resource limits defined',
    severity: 'info',
    defaultConfidence: 'medium',
    category: 'docker',
    description:
      'The service has no deploy.resources.limits, so it can consume unbounded CPU/memory on ' +
      'the host.',
    recommendation: 'Set deploy.resources.limits (cpus, memory) for every service.',
    references: COMPOSE_REFS,
  },
  {
    id: 'I016',
    title: 'Database port published without host IP restriction',
    severity: 'medium',
    defaultConfidence: 'medium',
    category: 'docker',
    description:
      'A well-known database port (5432/3306/6379/27017) is published without a host IP, ' +
      'binding it to every network interface instead of just localhost.',
    recommendation:
      'Bind published database ports to 127.0.0.1 (e.g. "127.0.0.1:5432:5432") or remove the ' +
      'port publication entirely and rely on the compose network.',
    references: COMPOSE_REFS,
  },

  // ---- Kubernetes (I02x) ----
  {
    id: 'I020',
    title: 'Privileged security context',
    severity: 'critical',
    defaultConfidence: 'high',
    category: 'infrastructure',
    description:
      "A container's securityContext sets privileged: true, giving it essentially all " +
      'capabilities of the host.',
    recommendation: 'Remove privileged: true; request only specific capabilities if needed.',
    references: K8S_REFS,
  },
  {
    id: 'I021',
    title: 'Host namespace sharing enabled',
    severity: 'high',
    defaultConfidence: 'high',
    category: 'infrastructure',
    description:
      'The pod spec sets hostNetwork, hostPID, or hostIPC to true, sharing that host namespace ' +
      'with every container in the pod.',
    recommendation:
      'Remove hostNetwork/hostPID/hostIPC unless the workload genuinely requires host ' +
      'namespace access, and prefer narrower alternatives when it does.',
    references: K8S_REFS,
  },
  {
    id: 'I022',
    title: 'Sensitive hostPath volume',
    severity: 'critical',
    defaultConfidence: 'high',
    category: 'infrastructure',
    description:
      'The pod spec mounts a hostPath volume pointing at the Docker socket (full node/daemon ' +
      'control), the host root or /etc (whole-node filesystem access), or another host path.',
    recommendation:
      'Avoid hostPath volumes; use a PersistentVolumeClaim or another cluster-managed storage ' +
      'mechanism instead.',
    references: K8S_REFS,
  },
  {
    id: 'I023',
    title: 'Container may run as root',
    severity: 'medium',
    defaultConfidence: 'medium',
    category: 'infrastructure',
    description:
      'Neither the container nor the pod securityContext sets runAsNonRoot, and runAsUser is ' +
      'either unset or 0, so the container can run as root.',
    recommendation:
      'Set securityContext.runAsNonRoot: true and a non-zero runAsUser at the pod or container ' +
      'level.',
    references: K8S_REFS,
  },
  {
    id: 'I024',
    title: 'Privilege escalation not blocked',
    severity: 'low',
    defaultConfidence: 'medium',
    category: 'infrastructure',
    description:
      'The container securityContext does not explicitly set allowPrivilegeEscalation: false, ' +
      'leaving privilege escalation via setuid binaries possible.',
    recommendation: 'Set securityContext.allowPrivilegeEscalation: false on every container.',
    references: K8S_REFS,
  },
  {
    id: 'I025',
    title: 'Added Linux capability',
    severity: 'critical',
    defaultConfidence: 'high',
    category: 'infrastructure',
    description:
      'The container securityContext adds a Linux capability: SYS_ADMIN/ALL (critical), ' +
      'NET_ADMIN/SYS_PTRACE (high), or another capability beyond the default set (low).',
    recommendation:
      'Drop ALL capabilities and add back only the specific, narrow capability the container ' +
      'actually needs.',
    references: K8S_REFS,
  },
  {
    id: 'I026',
    title: 'No resource limits defined',
    severity: 'info',
    defaultConfidence: 'medium',
    category: 'infrastructure',
    description:
      'The container has no resources.limits, so it can consume unbounded node resources.',
    recommendation: 'Set resources.limits (cpu, memory) on every container.',
    references: K8S_REFS,
  },
  {
    id: 'I027',
    title: 'Unpinned container image',
    severity: 'medium',
    defaultConfidence: 'high',
    category: 'infrastructure',
    description:
      'The container image has no tag (implicit :latest), an explicit :latest tag, or no ' +
      'digest, so the exact deployed image can change without a manifest change.',
    recommendation: 'Pin the image to an explicit version tag or a @sha256 digest.',
    references: K8S_REFS,
  },
  {
    id: 'I028',
    title: 'Hardcoded secret in container env',
    severity: 'high',
    defaultConfidence: 'medium',
    category: 'infrastructure',
    description:
      'A container env entry sets a literal, non-placeholder value on a variable whose name ' +
      'looks like a credential, instead of sourcing it from a Secret via valueFrom.',
    recommendation:
      'Move the value into a Kubernetes Secret and reference it with ' +
      'env[].valueFrom.secretKeyRef.',
    references: K8S_REFS,
  },

  // ---- Terraform (I03x) ----
  {
    id: 'I030',
    title: 'Security group ingress open to the internet',
    severity: 'high',
    defaultConfidence: 'high',
    category: 'infrastructure',
    description:
      'An ingress rule allows traffic from 0.0.0.0/0 or ::/0. Remote-admin ports (22/3389) or ' +
      'an all-ports/all-protocols rule are high severity; any other open port is medium.',
    recommendation:
      'Restrict ingress cidr_blocks/cidr_ipv4 to known, narrow ranges (a VPN or bastion CIDR), ' +
      'never 0.0.0.0/0 or ::/0, especially for administrative ports.',
    references: TF_REFS,
  },
  {
    id: 'I031',
    title: 'Public S3 bucket ACL',
    severity: 'high',
    defaultConfidence: 'high',
    category: 'infrastructure',
    description:
      'An S3 bucket (or bucket ACL resource) sets acl to public-read or public-read-write.',
    recommendation:
      'Remove the public canned ACL; use bucket policies plus S3 Block Public Access for any ' +
      'intentionally public content instead.',
    references: TF_REFS,
  },
  {
    id: 'I032',
    title: 'Hardcoded cloud credential',
    severity: 'critical',
    defaultConfidence: 'high',
    category: 'infrastructure',
    description:
      'A provider or resource block sets access_key, secret_key, or password to a literal ' +
      'string instead of a var./data. reference.',
    recommendation:
      'Remove the literal value; source credentials from a variable, environment-based ' +
      'provider auth, or a secret manager reference instead.',
    references: TF_REFS,
  },
  {
    id: 'I033',
    title: 'Encryption explicitly disabled',
    severity: 'medium',
    defaultConfidence: 'high',
    category: 'infrastructure',
    description:
      'A resource explicitly disables encryption at rest (encrypted = false, ' +
      'storage_encrypted = false, or server_side_encryption { enabled = false }).',
    recommendation:
      'Enable encryption at rest for the resource (remove the explicit false, or set it to ' +
      'true) unless there is a documented reason not to.',
    references: TF_REFS,
  },
];

export const RULE_META: ReadonlyMap<string, RuleDef> = new Map(
  RULE_DEFS.map((def) => [def.id, def]),
);

/** Look up a rule definition; throws on an unknown id (a programming error, not user input). */
export function ruleDef(id: string): RuleDef {
  const def = RULE_META.get(id);
  if (!def) throw new Error(`Unknown rule id: ${id}`);
  return def;
}

export function toRuleMetaList(): RuleMeta[] {
  return RULE_DEFS.map(
    ({
      id,
      title,
      severity,
      defaultConfidence,
      category,
      description,
      recommendation,
      references,
    }) => ({
      id,
      title,
      severity,
      defaultConfidence,
      category,
      description,
      recommendation,
      references,
    }),
  );
}
