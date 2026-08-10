import type { ScanLogger } from '@dl-sentinel/core';

/**
 * Fallback logger for entry points that take no logger of their own (the
 * public `loadConfig`). Warnings and errors go to stderr; debug/info are
 * dropped so a library call stays quiet unless something is wrong.
 */
export const stderrLogger: ScanLogger = {
  debug: () => {},
  info: () => {},
  warn: (message: string) => {
    console.warn(`dl-sentinel: ${message}`);
  },
  error: (message: string) => {
    console.error(`dl-sentinel: ${message}`);
  },
};
