/**
 * Human-readable scan progress, rendered to stderr so it never pollutes the
 * machine-parseable report on stdout. Only wired up when stderr is a TTY and
 * `--quiet` was not passed.
 */
import type { ScanEvent } from '@dl-sentinel/core';
import type { ColorFns } from './colors.js';

export interface ProgressReporter {
  onEvent(event: ScanEvent): void;
}

function plural(count: number, noun: string): string {
  return `${count} ${noun}${count === 1 ? '' : 's'}`;
}

export function createProgressReporter(
  write: (line: string) => void,
  colors: ColorFns,
): ProgressReporter {
  return {
    onEvent(event: ScanEvent): void {
      switch (event.type) {
        case 'scan:start':
          write(colors.bold(`Scanning ${event.target}`));
          write(
            colors.dim(`${plural(event.scanners.length, 'scanner')}: ${event.scanners.join(', ')}`),
          );
          break;
        case 'files:discovered':
          write(colors.dim(`Discovered ${plural(event.count, 'file')}`));
          break;
        case 'scanner:start':
          // Intentionally quiet — the completion line carries the useful detail.
          break;
        case 'scanner:complete':
          write(
            `  ${colors.green('OK')} ${event.scanner} ${colors.dim(
              `(${plural(event.findings, 'finding')}, ${event.durationMs}ms)`,
            )}`,
          );
          break;
        case 'scanner:error':
          write(`  ${colors.red('ERR')} ${event.scanner}: ${event.message}`);
          break;
        case 'scan:complete':
          write(
            colors.bold(
              `Completed in ${event.durationMs}ms — ${plural(event.findings, 'finding')}`,
            ),
          );
          break;
      }
    },
  };
}
