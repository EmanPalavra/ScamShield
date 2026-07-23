import { DurableObject } from "cloudflare:workers";

const MAX_LIMIT = 1_000;
const MAX_WINDOW_SECONDS = 24 * 60 * 60;

export interface RateLimitDecision {
  allowed: boolean;
  limit: number;
  remaining: number;
  retryAfter: number;
  resetAt: number;
}

export class RateLimiter extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS requests (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp_ms INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS requests_timestamp_idx
        ON requests (timestamp_ms);
    `);
  }

  check(limit: number, windowSeconds: number): RateLimitDecision {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_LIMIT) {
      throw new RangeError("Rate limit is outside the supported range.");
    }
    if (!Number.isSafeInteger(windowSeconds) || windowSeconds < 1 || windowSeconds > MAX_WINDOW_SECONDS) {
      throw new RangeError("Rate-limit window is outside the supported range.");
    }

    const now = Date.now();
    const windowMs = windowSeconds * 1_000;
    const cutoff = now - windowMs;

    return this.ctx.storage.transactionSync(() => {
      this.ctx.storage.sql.exec("DELETE FROM requests WHERE timestamp_ms <= ?", cutoff);
      const current = this.ctx.storage.sql
        .exec<{ request_count: number; earliest_ms: number | null }>(
          "SELECT COUNT(*) AS request_count, MIN(timestamp_ms) AS earliest_ms FROM requests",
        )
        .one();

      if (current.request_count >= limit) {
        const resetAt = (current.earliest_ms ?? now) + windowMs;
        return {
          allowed: false,
          limit,
          remaining: 0,
          retryAfter: Math.max(1, Math.ceil((resetAt - now) / 1_000)),
          resetAt,
        };
      }

      this.ctx.storage.sql.exec("INSERT INTO requests (timestamp_ms) VALUES (?)", now);
      const resetAt = (current.earliest_ms ?? now) + windowMs;
      return {
        allowed: true,
        limit,
        remaining: Math.max(0, limit - current.request_count - 1),
        retryAfter: 0,
        resetAt,
      };
    });
  }
}
