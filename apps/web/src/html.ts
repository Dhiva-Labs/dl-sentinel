/**
 * Minimal HTML-escaping helper. The dashboard's primary defense against
 * XSS from API-provided strings is building the DOM with `textContent` /
 * `createElement` (see public/app.js) rather than `innerHTML`; this helper
 * exists for the few spots (e.g. building a `title` attribute string) where
 * a plain string is assembled instead of DOM nodes, so that path is safe
 * too. Never used as a substitute for textContent when a DOM node is
 * available.
 */
const HTML_ESCAPES: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

const HTML_ESCAPE_PATTERN = /[&<>"']/g;

export function escapeHtml(value: string): string {
  return value.replace(HTML_ESCAPE_PATTERN, (ch) => HTML_ESCAPES[ch] ?? ch);
}
