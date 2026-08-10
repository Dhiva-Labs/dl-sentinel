/** Best-effort message for an unknown thrown value, without risking a `[object Object]`. */
export function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === 'string') return error;
  return String(error);
}
