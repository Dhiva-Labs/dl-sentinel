/**
 * Shared "is this container image reference pinned" check, used by the
 * Dockerfile `FROM` rule (I003) and the Kubernetes container image rule
 * (I027).
 *
 * An image is considered pinned when it carries a `@sha256:` digest
 * (strongest) or an explicit tag other than `latest`. It is considered
 * unpinned when it has no tag at all (Docker/Kubernetes both default an
 * untagged reference to `:latest`) or an explicit `:latest` tag.
 *
 * Registry host ports (`registry.example.com:5000/name`) are not mistaken
 * for tags: only the path segment after the final `/` is inspected for a
 * `:tag` suffix.
 */
export function isUnpinnedImageRef(image: string): boolean {
  const trimmed = image.trim();
  if (trimmed.length === 0) return false;
  if (trimmed.includes('@sha256:')) return false;

  const lastSlash = trimmed.lastIndexOf('/');
  const lastSegment = trimmed.slice(lastSlash + 1);
  const colonIdx = lastSegment.indexOf(':');
  if (colonIdx === -1) return true;

  const tag = lastSegment.slice(colonIdx + 1);
  return tag.toLowerCase() === 'latest';
}
