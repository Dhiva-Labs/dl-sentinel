/** JSON-pointer-ish path formatting for finding evidence, e.g. "paths./users.delete". */

export type PathSegment = string | number;

export function pointerPath(segments: readonly PathSegment[]): string {
  let out = '';
  for (const seg of segments) {
    if (typeof seg === 'number') {
      out += `[${seg}]`;
    } else if (out.length === 0) {
      out += seg;
    } else {
      out += `.${seg}`;
    }
  }
  return out;
}
