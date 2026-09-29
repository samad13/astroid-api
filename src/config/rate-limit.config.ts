import { registerAs } from '@nestjs/config';
import { rateLimitEnvSchema, validateEnv } from './env.validation';

/**
 * Optional tuning knob read outside the Zod environment schema (same pattern
 * as `BALANCE_CACHE_TTL`): a comma-separated list of extra client identifiers
 * folded into the public rate-limit bucket. Currently supports `apiKey`.
 */
function parseClientIdentifiers(): PublicRateLimitIdentifier[] {
  const raw = process.env.PUBLIC_RATE_LIMIT_CLIENT_IDENTIFIERS;
  if (!raw) {
    return [];
  }
  const known: PublicRateLimitIdentifier[] = ['ip', 'apiKey'];
  return raw
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry): entry is PublicRateLimitIdentifier =>
      known.includes(entry as PublicRateLimitIdentifier),
    );
}

/** Client identifiers that can participate in the public rate-limit bucket. */
export type PublicRateLimitIdentifier = 'ip' | 'apiKey';

/** Settings for the IP-based limiter applied to unauthenticated routes. */
export type PublicRateLimitConfig = {
  enabled: boolean;
  maxRequests: number;
  windowSeconds: number;
  trustProxy: boolean;
  /**
   * Identifiers folded into the bucket key. The client IP always
   * participates; 'apiKey' additionally separates key-holding clients
   * behind a shared address. Order defines bucket-key composition.
   */
  clientIdentifiers: PublicRateLimitIdentifier[];
};

export type RateLimitConfig = {
  windowSeconds: number;
  maxRequests: number;
  public: PublicRateLimitConfig;
};

/**
 * Config for the Redis-backed sliding-window rate limiters: the per-route
 * `SlidingWindowThrottlerGuard` (top-level fields) and the IP-based
 * `PublicRateLimitGuard` for public endpoints (`public`).
 */
/**
 * Parses the `PUBLIC_RATE_LIMIT_CLIENT_IDENTIFIERS` list. Unknown entries are
 * ignored so a typo cannot break startup; the IP always participates anyway.
 */
function parseClientIdentifiers(raw: string | undefined): PublicRateLimitIdentifier[] {
  if (!raw) {
    return [];
  }
  const known: PublicRateLimitIdentifier[] = ['ip', 'apiKey'];
  return raw
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry): entry is PublicRateLimitIdentifier =>
      known.includes(entry as PublicRateLimitIdentifier),
    );
}

export const rateLimitConfig = registerAs('rateLimit', (): RateLimitConfig => {
  const env = validateEnv(rateLimitEnvSchema, process.env);
  return {
    windowSeconds: env.RATE_LIMIT_WINDOW_SECONDS,
    maxRequests: env.RATE_LIMIT_MAX_REQUESTS,
    public: {
      enabled: env.PUBLIC_RATE_LIMIT_ENABLED,
      maxRequests: env.PUBLIC_RATE_LIMIT_MAX_REQUESTS,
      windowSeconds: env.PUBLIC_RATE_LIMIT_WINDOW_SECONDS,
      trustProxy: env.PUBLIC_RATE_LIMIT_TRUST_PROXY,
      clientIdentifiers: parseClientIdentifiers(),
    },
  };
});
