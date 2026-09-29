import { SetMetadata } from '@nestjs/common';

export const PUBLIC_RATE_LIMIT_RULE_KEY = 'astroid:publicRateLimitRule';

/** A `@PublicRateLimit()` rule: at most `max` requests per sliding `windowSeconds`. */
export interface PublicRateLimitRule {
  max: number;
  windowSeconds: number;
}

/**
 * Overrides the global IP rate-limit settings for a public route (or whole
 * controller) with a dedicated budget. Applies to routes covered by the
 * `PublicRateLimitGuard` — i.e. `@Public()` routes and `/<prefix>/public/*` —
 * and keeps the standard `X-RateLimit-*` header contract.
 */
export const PublicRateLimit = (max: number, windowSeconds: number) =>
  SetMetadata(PUBLIC_RATE_LIMIT_RULE_KEY, { max, windowSeconds } satisfies PublicRateLimitRule);
