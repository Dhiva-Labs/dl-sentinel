/**
 * Lite HCL parser for Terraform: enough structure to find `resource`/
 * `provider` blocks, their direct attributes, and named nested blocks
 * (`ingress`, `server_side_encryption`, ...), without evaluating HCL
 * expressions.
 *
 * Documented limitations (deliberate, not oversights):
 * - No expression evaluation: a value is only understood as a quoted
 *   string, a bracketed list of quoted strings, a bare number/boolean, or
 *   an opaque "reference-shaped" expression (used to detect var./data./
 *   local./module. references). Function calls, string interpolation
 *   beyond a raw `${...}` prefix check, and arithmetic are not evaluated.
 * - No heredoc (`<<EOT`) string support.
 * - `dynamic` blocks are treated as an ordinary nested block named
 *   "dynamic" (its label is skipped); its `content { }` body is not
 *   specially unwrapped.
 * - Top-level `resource "type" "name" {` / `provider "name" {` detection is
 *   a direct regex match against the source, not a full grammar parse, so a
 *   line that coincidentally looks like a block header inside a string or
 *   comment could confuse it — mitigated by requiring the match start to
 *   fall outside any string/comment region.
 */

export interface TfAttribute {
  key: string;
  /** Raw, unparsed value text (may itself be a quoted string, list, etc). */
  raw: string;
  /** Offset of the first character of the value (not the key). */
  offset: number;
}

export interface TfNestedBlock {
  name: string;
  bodyStart: number;
  bodyEnd: number;
  declOffset: number;
}

export interface TfBlock {
  kind: 'resource' | 'provider';
  type: string;
  name?: string;
  bodyStart: number;
  bodyEnd: number;
  declOffset: number;
}

/** 0 = ordinary code; 1 = inside a string literal or a comment (braces here don't count). */
export function classifyChars(text: string): Uint8Array {
  const n = text.length;
  const cls = new Uint8Array(n);
  let i = 0;
  while (i < n) {
    const c = text[i];
    if (c === '#') {
      while (i < n && text[i] !== '\n') {
        cls[i] = 1;
        i++;
      }
      continue;
    }
    if (c === '/' && text[i + 1] === '/') {
      while (i < n && text[i] !== '\n') {
        cls[i] = 1;
        i++;
      }
      continue;
    }
    if (c === '/' && text[i + 1] === '*') {
      cls[i] = 1;
      cls[i + 1] = 1;
      i += 2;
      while (i < n && !(text[i] === '*' && text[i + 1] === '/')) {
        cls[i] = 1;
        i++;
      }
      if (i < n) {
        cls[i] = 1;
        cls[i + 1] = 1;
        i += 2;
      }
      continue;
    }
    if (c === '"') {
      cls[i] = 1;
      i++;
      while (i < n && text[i] !== '"') {
        if (text[i] === '\\' && i + 1 < n) {
          cls[i] = 1;
          cls[i + 1] = 1;
          i += 2;
          continue;
        }
        cls[i] = 1;
        i++;
      }
      if (i < n) {
        cls[i] = 1;
        i++;
      }
      continue;
    }
    i++;
  }
  return cls;
}

/** Index of the `}` matching the `{` at `openIdx`, or -1 if unbalanced. */
export function findMatchingBrace(text: string, cls: Uint8Array, openIdx: number): number {
  let depth = 0;
  for (let i = openIdx; i < text.length; i++) {
    if (cls[i] === 1) continue;
    if (text[i] === '{') depth++;
    else if (text[i] === '}') {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

const IDENTIFIER_RE = /[A-Za-z_][A-Za-z0-9_-]*/y;

function skipQuotedString(text: string, from: number, end: number): number {
  let j = from + 1;
  while (j < end && text[j] !== '"') {
    if (text[j] === '\\' && j + 1 < end) j += 2;
    else j++;
  }
  return Math.min(j + 1, end);
}

/**
 * Scan a block body for direct attributes (`key = value`) and nested blocks
 * (`name { ... }` / `name "label" { ... }`), one nesting level at a time —
 * a nested block's own interior is not recursed into.
 */
export function scanBody(
  text: string,
  cls: Uint8Array,
  start: number,
  end: number,
): { attributes: TfAttribute[]; nested: TfNestedBlock[] } {
  const attributes: TfAttribute[] = [];
  const nested: TfNestedBlock[] = [];
  let i = start;

  while (i < end) {
    const c = text[i] ?? '';
    if (cls[i] === 1 || /\s/.test(c)) {
      i++;
      continue;
    }
    IDENTIFIER_RE.lastIndex = i;
    const idMatch = IDENTIFIER_RE.exec(text);
    if (!idMatch || idMatch.index !== i) {
      i++;
      continue;
    }
    const name = idMatch[0];
    let j = i + name.length;
    while (j < end && (text[j] === ' ' || text[j] === '\t')) j++;

    if (text[j] === '=' && text[j + 1] !== '=') {
      j++;
      while (j < end && (text[j] === ' ' || text[j] === '\t')) j++;
      const valueStart = j;
      if (text[j] === '"') {
        j = skipQuotedString(text, j, end);
      } else if (text[j] === '[' || text[j] === '{') {
        const openCh = text[j];
        const closeCh = openCh === '[' ? ']' : '}';
        let depth = 0;
        for (; j < end; j++) {
          if (cls[j] === 1) continue;
          if (text[j] === openCh) depth++;
          else if (text[j] === closeCh) {
            depth--;
            if (depth === 0) {
              j++;
              break;
            }
          }
        }
      } else {
        while (j < end && text[j] !== '\n' && cls[j] !== 1) j++;
      }
      const raw = text.slice(valueStart, j).trim();
      attributes.push({ key: name, raw, offset: valueStart });
      i = j;
      continue;
    }

    if (text[j] === '{') {
      const close = findMatchingBrace(text, cls, j);
      const bodyEnd = close === -1 ? end : close;
      nested.push({ name, bodyStart: j + 1, bodyEnd, declOffset: i });
      i = close === -1 ? end : close + 1;
      continue;
    }

    if (text[j] === '"') {
      // One or more quoted labels (block header) before the opening brace,
      // e.g. `dynamic "ingress" { ... }`.
      let k = j;
      while (text[k] === '"') {
        k = skipQuotedString(text, k, end);
        while (k < end && (text[k] === ' ' || text[k] === '\t')) k++;
      }
      if (text[k] === '{') {
        const close = findMatchingBrace(text, cls, k);
        const bodyEnd = close === -1 ? end : close;
        nested.push({ name, bodyStart: k + 1, bodyEnd, declOffset: i });
        i = close === -1 ? end : close + 1;
      } else {
        i = k;
      }
      continue;
    }

    i = j;
  }

  return { attributes, nested };
}

const RESOURCE_RE = /\bresource\s+"([^"]+)"\s+"([^"]+)"\s*\{/g;
const PROVIDER_RE = /\bprovider\s+"([^"]+)"\s*\{/g;

/** Find every top-level `resource`/`provider` block in the file. */
export function findTopLevelBlocks(text: string, cls: Uint8Array): TfBlock[] {
  const blocks: TfBlock[] = [];

  for (const match of text.matchAll(RESOURCE_RE)) {
    if (match.index === undefined || cls[match.index] === 1) continue;
    const openIdx = match.index + match[0].length - 1;
    const close = findMatchingBrace(text, cls, openIdx);
    blocks.push({
      kind: 'resource',
      type: match[1] ?? '',
      name: match[2],
      bodyStart: openIdx + 1,
      bodyEnd: close === -1 ? text.length : close,
      declOffset: match.index,
    });
  }

  for (const match of text.matchAll(PROVIDER_RE)) {
    if (match.index === undefined || cls[match.index] === 1) continue;
    const openIdx = match.index + match[0].length - 1;
    const close = findMatchingBrace(text, cls, openIdx);
    blocks.push({
      kind: 'provider',
      type: match[1] ?? '',
      bodyStart: openIdx + 1,
      bodyEnd: close === -1 ? text.length : close,
      declOffset: match.index,
    });
  }

  return blocks.sort((a, b) => a.declOffset - b.declOffset);
}

/** Attribute map for quick lookup by key (first occurrence wins). */
export function attributeMap(attributes: readonly TfAttribute[]): Map<string, TfAttribute> {
  const map = new Map<string, TfAttribute>();
  for (const attr of attributes) {
    if (!map.has(attr.key)) map.set(attr.key, attr);
  }
  return map;
}

/**
 * Unquote a simple `"..."` value, resolving backslash escapes character by
 * character. Returns undefined if `raw` isn't a plain quoted string.
 */
export function unquote(raw: string): string | undefined {
  const t = raw.trim();
  if (!(t.length >= 2 && t.startsWith('"') && t.endsWith('"'))) return undefined;
  const inner = t.slice(1, -1);
  const chars: string[] = [];
  for (let i = 0; i < inner.length; i++) {
    if (inner[i] === '\\' && i + 1 < inner.length) {
      const next = inner[i + 1] as string;
      if (next === 'n') chars.push('\n');
      else if (next === 't') chars.push('\t');
      else chars.push(next); // handles \" -> ", \\ -> \, and passes anything else through
      i++;
    } else {
      chars.push(inner[i] as string);
    }
  }
  return chars.join('');
}

/** Parse a `["a", "b"]`-shaped raw value into its unquoted string elements. */
export function parseStringList(raw: string): string[] {
  const t = raw.trim();
  if (!t.startsWith('[') || !t.endsWith(']')) return [];
  const inner = t.slice(1, -1);
  const items: string[] = [];
  let cur = '';
  let inStr = false;
  for (let i = 0; i < inner.length; i++) {
    const c = inner[i];
    if (c === '"' && inner[i - 1] !== '\\') inStr = !inStr;
    if (c === ',' && !inStr) {
      items.push(cur.trim());
      cur = '';
      continue;
    }
    cur += c;
  }
  if (cur.trim().length > 0) items.push(cur.trim());
  return items.map((s) => unquote(s)).filter((s): s is string => s !== undefined);
}

/** True when `raw` references a variable/data/local/module rather than being a plain literal. */
export function isReferenceExpression(raw: string): boolean {
  const t = raw.trim();
  if (/^(var|data|local|module)\./.test(t)) return true;
  const inner = unquote(t);
  if (inner !== undefined && /\$\{[^}]*\b(var|data|local|module)\./.test(inner)) return true;
  return false;
}

export function parseNumber(raw: string | undefined): number | undefined {
  if (raw === undefined) return undefined;
  const n = Number(raw.trim());
  return Number.isFinite(n) ? n : undefined;
}

export function parseBoolLiteral(raw: string | undefined): boolean | undefined {
  if (raw === undefined) return undefined;
  const t = raw.trim().toLowerCase();
  if (t === 'true') return true;
  if (t === 'false') return false;
  return undefined;
}
