/**
 * The rule-id vocabulary the correlation catalog reasons over.
 *
 * Every set is declared here rather than inline in a rule so that the
 * conditions a path claims are auditable in one place, and so the catalog
 * table in docs/attack-paths.md has a single source to mirror.
 *
 * Note the anchored patterns: `SC001` (smart contract) must never be mistaken
 * for an `S` secrets rule, so membership is tested with `/^S\d{3}$/`, never
 * with `startsWith('S')`.
 */
import type { Finding } from '@dl-sentinel/core';

/** A secrets-scanner rule id (`S001`-`S022`) — anchored so `SC0xx` cannot match. */
export const SECRET_RULE_ID = /^S\d{3}$/;
/** An infrastructure-scanner rule id (`I001`-`I033`). */
export const INFRA_RULE_ID = /^I\d{3}$/;
/** An API-scanner rule id (`A001`-`A010`). */
export const API_RULE_ID = /^A\d{3}$/;
/** A source-scanner rule id (`C001`-`C010`). */
export const SOURCE_RULE_ID = /^C\d{3}$/;

/**
 * Privileged / host-namespace configuration: the container or workload is not
 * meaningfully separated from the host it runs on.
 */
export const PRIVILEGED_RULES: ReadonlyMap<string, string> = new Map([
  ['I010', 'the compose service runs privileged, so container isolation does not apply'],
  ['I011', 'the compose service shares the host network namespace'],
  ['I013', 'the compose service adds a Linux capability that can escape the container'],
  ['I020', 'the pod container runs with a privileged security context'],
  ['I021', 'the workload shares a host namespace with the node'],
  ['I025', 'the pod container adds a Linux capability that can escape the container'],
]);

/**
 * Exposed-surface signals: something about the deployment puts a listening
 * service in front of a network the operator did not restrict.
 *
 * `I011`/`I021` appear here as well as in {@link PRIVILEGED_RULES} because
 * host networking is genuinely both: a container on the host network has every
 * port it listens on bound directly to the host's interfaces, with no port
 * mapping to review. A rule that uses both sets always requires the two
 * matched findings to be *different* findings, so a lone `I011` can never pair
 * with itself.
 */
export const EXPOSURE_RULES: ReadonlyMap<string, string> = new Map([
  ['I006', 'the image exposes an administrative port'],
  ['I016', 'a database port is published without a host-IP restriction'],
  ['I011', 'host network mode binds the service directly on the host interfaces'],
  ['I021', 'host networking binds the workload directly on the node interfaces'],
]);

/** Host filesystem reachable from inside the container. */
export const HOST_MOUNT_RULES: ReadonlyMap<string, string> = new Map([
  ['I012', 'a sensitive host path is mounted into the compose service'],
  ['I022', 'a sensitive hostPath volume is mounted into the pod'],
]);

/** A credential handed to the container through its environment. */
export const ENV_SECRET_RULES: ReadonlyMap<string, string> = new Map([
  ['I004', 'a credential is baked into the image as an ENV/ARG value'],
  ['I014', 'a credential is set in the compose service environment'],
  ['I028', 'a credential is set in the container environment'],
]);

/** Injection-class source findings: attacker-influenced data reaching an interpreter. */
export const INJECTION_RULES: ReadonlyMap<string, string> = new Map([
  ['C001', 'a shell command is built from application data'],
  ['C002', 'application data reaches a dynamic code evaluation'],
  ['C003', 'a SQL statement is built by string concatenation'],
]);

/** AWS key material — the credential half of a cloud-storage exposure chain. */
export const AWS_CREDENTIAL_RULES: ReadonlyMap<string, string> = new Map([
  ['S001', 'an AWS access key id is committed to the repository'],
  ['S002', 'an AWS secret access key is committed to the repository'],
]);

/** Unauthenticated API operations (`A001` no auth at all, `A005` state-changing). */
export const UNAUTHENTICATED_API_RULES: ReadonlyMap<string, string> = new Map([
  ['A001', 'the operation has no effective authentication requirement'],
  ['A005', 'a state-changing operation has no effective authentication requirement'],
]);

/** `I031` — a bucket ACL that grants public read. */
export const PUBLIC_BUCKET_RULE = 'I031';
/** `D001` — a dependency with a known vulnerability. */
export const VULNERABLE_DEPENDENCY_RULE = 'D001';
/** `A003` — a plain-http server URL or request. */
export const CLEARTEXT_TRANSPORT_RULE = 'A003';

/**
 * A secrets finding strong enough to anchor a chain: a real rule id (not
 * `SC0xx`) at critical or high severity. Medium/low secret findings are
 * detection heuristics whose value is often a placeholder — pairing them into
 * a path would manufacture alarm out of noise.
 */
export function isStrongSecret(finding: Finding): boolean {
  return (
    SECRET_RULE_ID.test(finding.ruleId) &&
    (finding.severity === 'critical' || finding.severity === 'high')
  );
}

/**
 * `A003` counts as an exposed cleartext surface only when the scanner did not
 * downgrade it to `info` — that downgrade means the URL is a localhost/
 * loopback address, i.e. a developer's own machine rather than a surface
 * anyone else can reach.
 */
export function isCleartextTransport(finding: Finding): boolean {
  return finding.ruleId === CLEARTEXT_TRANSPORT_RULE && finding.severity !== 'info';
}

/**
 * `I021` covers `hostNetwork`, `hostPID` and `hostIPC`. Only the first is a
 * network-exposure signal; the other two are privilege signals and stay in
 * {@link PRIVILEGED_RULES} alone.
 */
export function isNetworkExposure(finding: Finding): boolean {
  if (finding.ruleId === 'I021') return finding.metadata?.['field'] === 'hostNetwork';
  return EXPOSURE_RULES.has(finding.ruleId);
}

/** The declared reason a rule id belongs to a set, for step notes. */
export function reasonFor(set: ReadonlyMap<string, string>, ruleId: string): string {
  return set.get(ruleId) ?? 'the finding matches this rule set';
}
