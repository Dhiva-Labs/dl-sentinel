/**
 * Tiny ANSI color helper — hand-rolled so the CLI adds no dependency. Color is
 * opt-in: it is only enabled when the target stream is a TTY, the caller did
 * not pass `--no-color`, and `NO_COLOR` is not set (https://no-color.org).
 * Report/table text is padded before it is wrapped, so the zero-width escape
 * codes never disturb column alignment; when disabled, every function is the
 * identity, so output stays plain and machine-parseable.
 */

export interface ColorFns {
  readonly enabled: boolean;
  bold(text: string): string;
  dim(text: string): string;
  red(text: string): string;
  green(text: string): string;
  yellow(text: string): string;
  blue(text: string): string;
  magenta(text: string): string;
  cyan(text: string): string;
  gray(text: string): string;
}

export interface ColorDecision {
  /** The `--no-color` flag was passed. */
  readonly noColorFlag: boolean;
  readonly env: NodeJS.ProcessEnv;
  /** The destination stream is a TTY. */
  readonly isTTY: boolean;
}

/** Decide whether ANSI color should be emitted for a given stream. */
export function shouldColor({ noColorFlag, env, isTTY }: ColorDecision): boolean {
  if (noColorFlag) return false;
  // NO_COLOR disables color when set to any non-empty value.
  const noColor = env.NO_COLOR;
  if (typeof noColor === 'string' && noColor !== '') return false;
  return isTTY;
}

export function makeColors(enabled: boolean): ColorFns {
  const esc = String.fromCharCode(27);
  const wrap =
    (open: number, close: number) =>
    (text: string): string =>
      enabled ? `${esc}[${open}m${text}${esc}[${close}m` : text;
  return {
    enabled,
    bold: wrap(1, 22),
    dim: wrap(2, 22),
    red: wrap(31, 39),
    green: wrap(32, 39),
    yellow: wrap(33, 39),
    blue: wrap(34, 39),
    magenta: wrap(35, 39),
    cyan: wrap(36, 39),
    gray: wrap(90, 39),
  };
}
