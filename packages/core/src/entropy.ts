/**
 * Shannon entropy in bits per character. High-entropy strings (> ~4.0 for
 * mixed-case alphanumerics) are a signal for machine-generated secrets.
 */
export function shannonEntropy(value: string): number {
  const chars = Array.from(value);
  if (chars.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of chars) {
    freq.set(ch, (freq.get(ch) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / chars.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}
