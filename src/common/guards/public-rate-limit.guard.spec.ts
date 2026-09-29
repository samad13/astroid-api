import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ExecutionContext, Logger } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { Redis } from 'ioredis';
import { PublicRateLimitGuard } from './public-rate-limit.guard';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';
import { SKIP_PUBLIC_RATE_LIMIT_KEY } from '../decorators/skip-public-rate-limit.decorator';
import { DomainException } from '../exceptions/domain.exception';
import { ErrorCode } from '../constants/error-codes';
import { PublicRateLimitConfig } from '../../config/rate-limit.config';
import { PUBLIC_RATE_LIMIT_RULE_KEY } from '../decorators/public-rate-limit.decorator';

type Metadata = { public?: boolean; skip?: boolean; rule?: { max: number; windowSeconds: number } };

function buildContext(
  request: { path?: string; ip?: string; headers?: Record<string, string | string[]> },
  metadata: Metadata = {},
) {
  const headers: Record<string, unknown> = {};
  const response = { setHeader: vi.fn((name: string, value: unknown) => (headers[name] = value)) };
  const handler = () => undefined;
  class TestController {}
  if (metadata.public) Reflect.defineMetadata(IS_PUBLIC_KEY, true, handler);
  if (metadata.skip) Reflect.defineMetadata(SKIP_PUBLIC_RATE_LIMIT_KEY, true, handler);
  if (metadata.rule)
    Reflect.defineMetadata(PUBLIC_RATE_LIMIT_RULE_KEY, metadata.rule, handler);

  const context = {
    getType: () => 'http',
    getHandler: () => handler,
    getClass: () => TestController,
    switchToHttp: () => ({
      getRequest: () => ({ path: '/api/v1/auth/login', ip: '203.0.113.7', headers: {}, ...request }),
      getResponse: () => response,
    }),
  } as unknown as ExecutionContext;
  return { context, headers, response };
}

function buildGuard(
  overrides: Partial<PublicRateLimitConfig> = {},
  redis: Partial<Record<'status' | 'eval', unknown>> = { status: 'end' },
) {
  const settings: PublicRateLimitConfig = {
    enabled: true,
    maxRequests: 3,
    windowSeconds: 60,
    trustProxy: false,
    clientIdentifiers: [],
    ...overrides,
  };
  const config = {
    getOrThrow: vi.fn(() => ({ windowSeconds: 60, maxRequests: 120, public: settings })),
    get: vi.fn(() => ({ apiPrefix: 'api/v1' })),
  } as unknown as ConfigService;
  return new PublicRateLimitGuard(new Reflector(), config, redis as unknown as Redis);
}

async function expectRateLimited(promise: Promise<boolean>) {
  const error = await promise.catch((e: unknown) => e);
  expect(error).toBeInstanceOf(DomainException);
  expect((error as DomainException).code).toBe(ErrorCode.RATE_LIMITED);
  expect((error as DomainException).getStatus()).toBe(429);
  return error as DomainException;
}

describe('PublicRateLimitGuard', () => {
  beforeEach(() => {
    vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
    vi.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined);
  });

  describe('route selection', () => {
    it('ignores authenticated routes', async () => {
      const guard = buildGuard({ maxRequests: 1 });
      const { context, response } = buildContext({ path: '/api/v1/agents' });

      for (let i = 0; i < 5; i++) {
        await expect(guard.canActivate(context)).resolves.toBe(true);
      }
      expect(response.setHeader).not.toHaveBeenCalled();
    });

    it('limits routes marked @Public()', async () => {
      const guard = buildGuard({ maxRequests: 1 });
      const { context } = buildContext({}, { public: true });

      await guard.canActivate(context);
      await expectRateLimited(guard.canActivate(context));
    });

    it('limits every route under /<prefix>/public/', async () => {
      const guard = buildGuard({ maxRequests: 1 });
      const { context } = buildContext({ path: '/api/v1/public/status' });

      await guard.canActivate(context);
      await expectRateLimited(guard.canActivate(context));
    });

    it('does not treat look-alike paths as public', async () => {
      const guard = buildGuard({ maxRequests: 1 });
      const { context } = buildContext({ path: '/api/v1/publications' });

      await guard.canActivate(context);
      await expect(guard.canActivate(context)).resolves.toBe(true);
    });

    it('honours @SkipPublicRateLimit() on public routes', async () => {
      const guard = buildGuard({ maxRequests: 1 });
      const { context } = buildContext({}, { public: true, skip: true });

      await guard.canActivate(context);
      await expect(guard.canActivate(context)).resolves.toBe(true);
    });

    it('does nothing when disabled', async () => {
      const guard = buildGuard({ enabled: false, maxRequests: 1 });
      const { context } = buildContext({}, { public: true });

      await guard.canActivate(context);
      await expect(guard.canActivate(context)).resolves.toBe(true);
    });
  });

  describe('headers', () => {
    it('sets X-RateLimit-Limit, -Remaining and -Reset on allowed requests', async () => {
      vi.useFakeTimers({ now: 1_750_000_000_000 });
      try {
        const guard = buildGuard({ maxRequests: 3, windowSeconds: 60 });
        const { context, headers } = buildContext({}, { public: true });

        await guard.canActivate(context);

        expect(headers['X-RateLimit-Limit']).toBe(3);
        expect(headers['X-RateLimit-Remaining']).toBe(2);
        expect(headers['X-RateLimit-Reset']).toBe(Math.ceil((1_750_000_000_000 + 60_000) / 1000));
        expect(headers['Retry-After']).toBeUndefined();
      } finally {
        vi.useRealTimers();
      }
    });

    it('counts Remaining down to zero across a burst', async () => {
      const guard = buildGuard({ maxRequests: 3 });
      const remaining: unknown[] = [];

      for (let i = 0; i < 3; i++) {
        const { context, headers } = buildContext({}, { public: true });
        await guard.canActivate(context);
        remaining.push(headers['X-RateLimit-Remaining']);
      }

      expect(remaining).toEqual([2, 1, 0]);
    });

    it('returns 429 with Retry-After and zero Remaining once the burst exceeds the limit', async () => {
      const guard = buildGuard({ maxRequests: 3, windowSeconds: 60 });
      for (let i = 0; i < 3; i++) {
        await guard.canActivate(buildContext({}, { public: true }).context);
      }
      const { context, headers } = buildContext({}, { public: true });

      const error = await expectRateLimited(guard.canActivate(context));

      expect(headers['X-RateLimit-Remaining']).toBe(0);
      expect(headers['Retry-After']).toBeGreaterThanOrEqual(1);
      expect(headers['Retry-After']).toBeLessThanOrEqual(60);
      expect(error.details).toMatchObject({ limit: 3, windowSeconds: 60 });
    });
  });

  describe('client identification', () => {
    it('buckets by client IP', async () => {
      const guard = buildGuard({ maxRequests: 1 });

      await guard.canActivate(buildContext({ ip: '198.51.100.1' }, { public: true }).context);

      await expect(
        guard.canActivate(buildContext({ ip: '198.51.100.2' }, { public: true }).context),
      ).resolves.toBe(true);
      await expectRateLimited(
        guard.canActivate(buildContext({ ip: '198.51.100.1' }, { public: true }).context),
      );
    });

    it('ignores X-Forwarded-For unless the proxy is trusted', async () => {
      const guard = buildGuard({ maxRequests: 1, trustProxy: false });
      const spoofed = (value: string) =>
        buildContext({ headers: { 'x-forwarded-for': value } }, { public: true }).context;

      await guard.canActivate(spoofed('10.0.0.1'));

      await expectRateLimited(guard.canActivate(spoofed('10.0.0.2')));
    });

    it('uses the first X-Forwarded-For entry behind a trusted proxy', async () => {
      const guard = buildGuard({ maxRequests: 1, trustProxy: true });
      const forwarded = (value: string) =>
        buildContext({ headers: { 'x-forwarded-for': value } }, { public: true }).context;

      await guard.canActivate(forwarded('10.0.0.1, 172.16.0.1'));

      await expect(guard.canActivate(forwarded('10.0.0.2, 172.16.0.1'))).resolves.toBe(true);
      await expectRateLimited(guard.canActivate(forwarded('10.0.0.1, 172.16.0.9')));
    });
  });

  describe('per-route rules', () => {
    it('applies the @PublicRateLimit() override instead of the global limit', async () => {
      const guard = buildGuard({ maxRequests: 1 });
      const { context, headers } = buildContext(
        {},
        { public: true, rule: { max: 2, windowSeconds: 30 } },
      );

      await guard.canActivate(context);
      await guard.canActivate(context);
      const limited = await expectRateLimited(guard.canActivate(context));

      expect(headers['X-RateLimit-Limit']).toBe(2);
      expect(limited.details).toMatchObject({ limit: 2, windowSeconds: 30 });
    });

    it('keeps the global default when no route override is present', async () => {
      const guard = buildGuard({ maxRequests: 2 });
      const { context, headers } = buildContext({}, { public: true });

      await guard.canActivate(context);

      expect(headers['X-RateLimit-Limit']).toBe(2);
    });

    it('honours controller-level overrides over handler rules', async () => {
      const guard = buildGuard({ maxRequests: 5 });
      // The handler rule must win (getAllAndOverride walks handler first).
      const { context, headers } = buildContext(
        {},
        { public: true, rule: { max: 4, windowSeconds: 15 } },
      );

      await guard.canActivate(context);

      expect(headers['X-RateLimit-Limit']).toBe(4);
    });

    it('lets @SkipPublicRateLimit() bypass a route-level rule too', async () => {
      const guard = buildGuard({ maxRequests: 1 });
      const { context } = buildContext(
        {},
        { public: true, skip: true, rule: { max: 1, windowSeconds: 60 } },
      );

      await expect(guard.canActivate(context)).resolves.toBe(true);
      await expect(guard.canActivate(context)).resolves.toBe(true);
    });
  });

  describe('client identifiers', () => {
    it('buckets API-key callers separately from their shared IP when enabled', async () => {
      const guard = buildGuard({ maxRequests: 1, clientIdentifiers: ['apiKey'] });
      const withKey = (key: string) =>
        buildContext({ headers: { 'x-api-key': key } }, { public: true }).context;

      // Exhaust the plain-IP bucket first: the (max+1)th keyless hit is limited.
      await guard.canActivate(buildContext({}, { public: true }).context);
      await expectRateLimited(guard.canActivate(buildContext({}, { public: true }).context));

      // Key-holding callers get their own budgets despite the same IP.
      await guard.canActivate(withKey('ak_live_aaaa'));
      await guard.canActivate(withKey('ak_live_bbbb'));
    });

    it('ignores API keys when no client identifiers are configured', async () => {
      const guard = buildGuard({ maxRequests: 1, clientIdentifiers: [] });
      const withKey = (key: string) =>
        buildContext({ headers: { 'x-api-key': key } }, { public: true }).context;

      await guard.canActivate(withKey('ak_live_aaaa'));

      // Without identifier tracking, a second key on the same IP is limited.
      await expectRateLimited(guard.canActivate(withKey('ak_live_bbbb')));
    });

    it('counts an ApiKey Authorization header the same as x-api-key', async () => {
      const guard = buildGuard({ maxRequests: 1, clientIdentifiers: ['apiKey'] });
      const context = buildContext(
        { headers: { authorization: 'ApiKey ak_live_aaaa' } },
        { public: true },
      ).context;

      await guard.canActivate(context);

      await expectRateLimited(
        guard.canActivate(
          buildContext({ headers: { 'x-api-key': 'ak_live_aaaa' } }, { public: true }).context,
        ),
      );
    });
  });

  describe('storage', () => {
    it('records hits in Redis under a per-IP key when Redis is ready', async () => {
      const evalFn = vi.fn().mockResolvedValue([1, 1, Date.now() + 60_000]);
      const guard = buildGuard({}, { status: 'ready', eval: evalFn });

      await guard.canActivate(buildContext({ ip: '198.51.100.9' }, { public: true }).context);

      expect(evalFn).toHaveBeenCalledTimes(1);
      expect(evalFn.mock.calls[0][2]).toBe('rate-limit:public:ip:198.51.100.9');
    });

    it('rejects when Redis reports the window is full', async () => {
      const evalFn = vi.fn().mockResolvedValue([0, 3, Date.now() + 30_000]);
      const guard = buildGuard({ maxRequests: 3 }, { status: 'ready', eval: evalFn });
      const { context, headers } = buildContext({}, { public: true });

      await expectRateLimited(guard.canActivate(context));
      expect(headers['Retry-After']).toBe(30);
    });

    it('keeps enforcing limits in memory when a Redis call fails', async () => {
      const evalFn = vi.fn().mockRejectedValue(new Error('READONLY'));
      const guard = buildGuard({ maxRequests: 1 }, { status: 'ready', eval: evalFn });
      const { context } = buildContext({}, { public: true });

      await expect(guard.canActivate(context)).resolves.toBe(true);
      await expectRateLimited(guard.canActivate(context));
      expect(Logger.prototype.warn).toHaveBeenCalledTimes(1);
    });

    it('skips Redis entirely while the client is not ready', async () => {
      const evalFn = vi.fn();
      const guard = buildGuard({ maxRequests: 1 }, { status: 'reconnecting', eval: evalFn });
      const { context } = buildContext({}, { public: true });

      await guard.canActivate(context);
      await expectRateLimited(guard.canActivate(context));
      expect(evalFn).not.toHaveBeenCalled();
    });
  });
});
