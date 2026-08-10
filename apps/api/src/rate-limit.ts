interface Bucket {
  count: number;
  resetAt: number;
}

export interface RateLimitResult {
  allowed: boolean;
  /** Milliseconds until the current window resets (only meaningful when blocked). */
  retryAfterMs: number;
  /** Requests remaining in the current window. */
  remaining: number;
}

/**
 * Fixed-window, in-memory rate limiter keyed by an arbitrary string (token id
 * or client IP). Bounded memory: expired buckets are swept lazily once the map
 * grows past a threshold, and no timers are used so the process stays free to
 * exit cleanly.
 */
export class RateLimiter {
  private readonly buckets = new Map<string, Bucket>();
  private readonly windowMs: number;
  private readonly max: number;
  private readonly now: () => number;
  private static readonly SWEEP_THRESHOLD = 4096;

  constructor(windowMs: number, max: number, now: () => number = Date.now) {
    this.windowMs = windowMs;
    this.max = max;
    this.now = now;
  }

  check(key: string): RateLimitResult {
    const t = this.now();
    let bucket = this.buckets.get(key);
    if (bucket === undefined || t >= bucket.resetAt) {
      bucket = { count: 0, resetAt: t + this.windowMs };
      this.buckets.set(key, bucket);
    }
    if (bucket.count >= this.max) {
      return { allowed: false, retryAfterMs: Math.max(0, bucket.resetAt - t), remaining: 0 };
    }
    bucket.count += 1;
    if (this.buckets.size > RateLimiter.SWEEP_THRESHOLD) this.sweep(t);
    return { allowed: true, retryAfterMs: 0, remaining: this.max - bucket.count };
  }

  private sweep(t: number): void {
    for (const [key, bucket] of this.buckets) {
      if (t >= bucket.resetAt) this.buckets.delete(key);
    }
  }
}
