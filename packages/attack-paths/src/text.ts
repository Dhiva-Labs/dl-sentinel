/**
 * Narrative phrasing helpers.
 *
 * The house style is binding (docs/attack-paths.md "The honesty contract"):
 * every narrative says what the combination **could allow**, never what an
 * attacker *will* do and never that anything is *exploitable*. These helpers
 * exist so the phrasing is assembled in one place rather than re-typed — the
 * package's tests sweep every narrative and note for the banned wording.
 */

/** Turn a lowercase reason clause into a sentence for a step note. */
export function asNote(reason: string): string {
  return `${reason.charAt(0).toUpperCase()}${reason.slice(1)}.`;
}

/** Join non-empty sentences into a narrative. */
export function narrative(...sentences: readonly string[]): string {
  return sentences.filter((sentence) => sentence.length > 0).join(' ');
}

/** `1 finding` / `3 findings` — counts read as prose, not as `3 finding(s)`. */
export function plural(count: number, noun: string): string {
  return `${String(count)} ${noun}${count === 1 ? '' : 's'}`;
}
