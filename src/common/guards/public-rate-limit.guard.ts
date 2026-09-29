import { CanActivate, ExecutionContext, Inject, Injectable, Logger } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { Redis } from 'ioredis';
import { Request, Response } from 'express';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';
import { SKIP_PUBLIC_RATE_LIMIT_KEY } from '../decorators/skip-public-rate-limit.decorator';
import {
  PUBLIC_RATE_LIMIT_RULE_KEY,
  PublicRateLimitRule,
} from '../decorators/public-rate-limit.decorator';
import { DomainException } from '../exceptions/domain.exception';
import { ErrorCode } from '../constants/error-codes';
import { REDIS_CLIENT } from '../locks/locks.constants';
import {
  MemorySlidingWindowStore,
  RedisSlidingWindowStore,
  SlidingWindowHit,
} from '../throttler/sliding-window.store';
import { PublicRateLimitConfig, RateLimitConfig } from '../../config/rate-limit.config';
import { AppConfig } from '../../config/app.config';
import { getClientIp } from '../../utils/ip.util';
import { extractApiKeyFromRequest } from '../helpers/extract-api-key';

export const RATE_LIMIT_LIMIT_HEADER = 'X-RateLimit-Limit';
export const RATE_LIMIT_REMAINING_HEADER = 'X-RateLimit-Remaining';
export const RATE_LIMIT_RESET_HEADER = 'X-RateLimit-Reset';

/** Outcome of evaluating one request against the public rate limiter. */
export interface PublicRateLimitResult {
  /** Whether the request fits within the applicable limit. */
  allowed: boolean;
  /** The limit in force for this request (global default or route override). */
  limit: number;
  /** Window length, in seconds, of the rule that produced the decision. */
  windowSeconds: number;
  /** Requests counted for this client in the current window, including this one. */
  count: number;
  /** Epoch ms at which the oldest counted request leaves the window. */
  resetAt: number;
}

/**
 * IP-and-client-based sliding-window rate limiter for unauthenticated
 * endpoints, the first line of defence against abuse, scraping and
 * denial-of-service bursts.
 *
 * Applies to every route marked `@Public()` and to every route under
 * `/<API_PREFIX>/public/`, unless exempted with `@SkipPublicRateLimit()`.
 * Authenticated routes are left to the per-organization throttlers.
 *
 * Requests are tracked per client identifier: the client IP always
 * participates, and when the limiter is configured with
 * `clientIdentifiers: ['ip', 'apiKey']` a presented API key (`x-api-key` /
 * `Authorization: ApiKey|Bearer ak_…`) is folded into the bucket key so
 * distinct programmatic clients behind one shared address (NAT, office
 * egress, CI runners) each get their own budget instead of a shared one.
 *
 * Every limited response carries `X-RateLimit-Limit`, `X-RateLimit-Remaining`
 * and `X-RateLimit-Reset` (epoch seconds at which a slot frees up); rejected
 * requests get `429 Too Many Requests` plus `Retry-After`.
 *
 * Counters live in Redis (the shared `REDIS_CLIENT`) so every replica enforces
 * one budget per client. If Redis is unavailable the guard falls back to a
 * per-process in-memory window rather than failing open, so public endpoints
 * stay protected during an outage.
 *
 * Limits are configurable in two layers: global defaults from
 * `PUBLIC_RATE_LIMIT_*` env vars, overridden per route (or controller) with
 * the `@PublicRateLimit(max, windowSeconds)` decorator.
 *
 * Implemented as a guard rather than Express middleware because middleware
 * runs before routing and cannot see the `@Public()` metadata.
 */
@Injectable()
export class PublicRateLimitGuard implements CanActivate {
  private readonly logger = new Logger(PublicRateLimitGuard.name);
  private readonly settings: PublicRateLimitConfig;
  private readonly publicPathPrefix: string;
  private readonly redisStore: RedisSlidingWindowStore;
  private readonly fallbackStore = new MemorySlidingWindowStore();
  private usingFallback = false;

  constructor(
    private readonly reflector: Reflector,
    config: ConfigService,
    @Inject(REDIS_CLIENT) redis: Redis,
  ) {
    this.settings = config.getOrThrow<RateLimitConfig>('rateLimit').public;
    const apiPrefix = config.get<AppConfig>('app')?.apiPrefix ?? '';
    this.publicPathPrefix = `/${[apiPrefix, 'public'].join('/')}`.replace(/\/{2,}/g, '/');
    this.redisStore = new RedisSlidingWindowStore(redis);
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    if (!this.settings.enabled || context.getType() !== 'http') {
      return true;
    }

    const request = context.switchToHttp().getRequest<Request>();
    if (!this.appliesTo(context, request)) {
      return true;
    }

    const result = await this.check(request, context);
    const response = context.switchToHttp().getResponse<Response>();
    response.setHeader(RATE_LIMIT_LIMIT_HEADER, result.limit);
    response.setHeader(RATE_LIMIT_REMAINING_HEADER, Math.max(0, result.limit - result.count));
    response.setHeader(RATE_LIMIT_RESET_HEADER, Math.ceil(result.resetAt / 1000));

    if (!result.allowed) {
      const now = Date.now();
      const retryAfterSeconds = Math.max(1, Math.ceil((result.resetAt - now) / 1000));
      response.setHeader('Retry-After', retryAfterSeconds);
      throw new DomainException(
        ErrorCode.RATE_LIMITED,
        'Too many requests from this IP address. Please retry later.',
        { limit: result.limit, windowSeconds: result.windowSeconds, retryAfterSeconds },
      );
    }

    return true;
  }

  /**
   * Records one hit against the client's sliding-window budget. The rule in
   * force is the route-level `@PublicRateLimit()` override when present, the
   * global `PUBLIC_RATE_LIMIT_*` settings otherwise.
   */
  async check(request: Request, context?: ExecutionContext): Promise<PublicRateLimitResult> {
    const rule = this.resolveRule(context);
    const now = Date.now();
    const key = `rate-limit:public:${this.clientBucket(request)}`;
    const hit = await this.record(key, rule.max, rule.windowSeconds * 1000, now);

    return {
      allowed: hit.allowed,
      limit: rule.max,
      windowSeconds: rule.windowSeconds,
      count: hit.count,
      resetAt: hit.resetAt,
    };
  }

  private appliesTo(context: ExecutionContext, request: Request): boolean {
    const targets = [context.getHandler(), context.getClass()];
    if (this.reflector.getAllAndOverride<boolean>(SKIP_PUBLIC_RATE_LIMIT_KEY, targets)) {
      return false;
    }
    if (this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, targets)) {
      return true;
    }
    const path = request.path ?? '';
    return path === this.publicPathPrefix || path.startsWith(`${this.publicPathPrefix}/`);
  }

  /** Route-level rule override wins; the global settings are the default. */
  private resolveRule(context?: ExecutionContext): PublicRateLimitRule {
    const defaults: PublicRateLimitRule = {
      max: this.settings.maxRequests,
      windowSeconds: this.settings.windowSeconds,
    };
    if (!context) {
      return defaults;
    }
    const targets = [context.getHandler(), context.getClass()];
    return this.reflector.getAllAndOverride<PublicRateLimitRule>(PUBLIC_RATE_LIMIT_RULE_KEY, targets) ?? defaults;
  }

  /**
   * Builds the bucket identifier for the caller. The IP always participates;
   * configured client identifiers (currently the API key) are appended so
   * distinct clients behind one address are tracked separately.
   */
  private clientBucket(request: Request): string {
    const parts = [`ip:${this.clientIp(request)}`];
    for (const identifier of this.settings.clientIdentifiers ?? []) {
      if (identifier === 'apiKey') {
        const apiKey = extractApiKeyFromRequest(request);
        if (apiKey) {
          parts.push(`key:${apiKey}`);
        }
      }
    }
    return parts.join(':');
  }

  /** Records the hit in Redis, degrading to the in-memory window on outage. */
  private async record(
    key: string,
    limit: number,
    windowMs: number,
    now: number,
  ): Promise<SlidingWindowHit> {
    if (this.redisStore.isReady) {
      try {
        const hit = await this.redisStore.hit(key, limit, windowMs, now);
        if (this.usingFallback) {
          this.usingFallback = false;
          this.logger.log('Redis is reachable again; public rate limits are shared across instances.');
        }
        return hit;
      } catch (error) {
        this.enterFallback(`Redis rate-limit check failed: ${(error as Error).message}`);
      }
    } else {
      this.enterFallback('Redis is not ready');
    }
    return this.fallbackStore.hit(key, limit, windowMs, now);
  }

  private enterFallback(reason: string): void {
    if (!this.usingFallback) {
      this.usingFallback = true;
      this.logger.warn(`${reason}; enforcing public rate limits per instance in memory.`);
    }
  }

  private clientIp(request: Request): string {
    const forwarded = request.headers?.['x-forwarded-for'];
    const forwardedFor = Array.isArray(forwarded) ? forwarded[0] : forwarded;
    const ip = request.ip ?? request.socket?.remoteAddress ?? 'unknown';
    return getClientIp(ip, forwardedFor, this.settings.trustProxy);
  }
}
