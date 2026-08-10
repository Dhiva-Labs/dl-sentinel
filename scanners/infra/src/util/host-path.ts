/**
 * Shared host-path severity tiering, used by the compose host-mount rule
 * (I012) and the Kubernetes hostPath volume rule (I022): mounting the Docker
 * socket is a critical container-escape vector, mounting `/` or `/etc`
 * exposes the whole host filesystem, anything else is a lesser but still
 * real host-boundary crossing.
 */
export type HostPathSeverity = 'critical' | 'high' | 'medium';

function normalize(hostPath: string): string {
  const trimmed = hostPath.trim();
  if (trimmed.length > 1) return trimmed.replace(/\/+$/, '');
  return trimmed;
}

export function isDockerSocketPath(hostPath: string): boolean {
  return normalize(hostPath).endsWith('docker.sock');
}

export function classifyHostPathSeverity(hostPath: string): HostPathSeverity {
  const normalized = normalize(hostPath);
  if (isDockerSocketPath(normalized)) return 'critical';
  if (normalized === '/' || normalized === '/etc') return 'high';
  return 'medium';
}

/**
 * Compose bind-mount sources are host paths only when they look like a
 * filesystem path (`/abs`, `./rel`, `../rel`, `~/rel`); a bare word
 * (`mydata`) is a named volume reference, not a host mount, and must not be
 * flagged by I012.
 */
export function looksLikeHostPathSource(source: string): boolean {
  return (
    source.startsWith('/') ||
    source.startsWith('./') ||
    source.startsWith('../') ||
    source.startsWith('~/') ||
    source === '~'
  );
}
