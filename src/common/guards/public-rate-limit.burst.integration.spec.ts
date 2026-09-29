import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { ConfigService } from '@nestjs/config';
import { Controller, Get, INestApplication, Logger, Post } from '@nestjs/common';
import { APP_FILTER, APP_GUARD } from '@nestjs/core';
import { Test } from '@nestjs/testing';
import { PublicRateLimitGuard } from './public-rate-limit.guard';
import { Public } from '../decorators/public.decorator';
import { PublicRateLimit } from '../decorators/public-rate-limit.decorator';
import { AllExceptionsFilter } from '../filters/all-exceptions.filter';
import { REDIS_CLIENT } from '../locks/locks.constants';
import { MemorySlidingWindowStore } from '../throttler/sliding-window.store';

/**
 * Sends request bursts over real HTTP against a Nest app wired like
 * production: the guard is a global APP_GUARD, errors go through
 * AllExceptionsFilter, and routes live under the `api/v1` prefix. The Redis
 * client is a stand-in whose `eval` reproduces the sliding-window script's
 * contract (`[allowed, count, resetAt]`) on top of the in-memory store, so the
 * Redis code path of the guard is exercised end to end.
 */

const GLOBAL_LIMIT = 4;

@Controller('auth')
class AuthController {
  @Public()
  @Post('login')
  login() {
    return { ok: true };
  }
}

@Controller('agents')
class AgentsController {
  @Get()
  list() {
    return [];
  }
}

@Controller('public')
class PublicCatalogController {
  @Get('status')
  status() {
    return { ok: true };
  }

  // A heavier endpoint with its own, stricter budget.
  @PublicRateLimit(2, 60)
  @Get('search')
  search() {
    return { ok: true };
  }
}

function fakeRedis() {
  const store = new MemorySlidingWindowStore();
  return {
    status: 'ready',
    eval: vi.fn(
      async (
        _script: string,
        _keys: number,
        key: string,
        now: number,
        windowMs: number,
        limit: number,
      ) => {
        const hit = await store.hit(key, limit, windowMs, now);
        return [hit.allowed ? 1 : 0, hit.count, hit.resetAt];
      },
    ),
  };
}

describe('Public API rate limiting (integration)', () => {
  let app: INestApplication;
  let baseUrl: string;
  let redis: ReturnType<typeof fakeRedis>;

  beforeAll(async () => {
    vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
    redis = fakeRedis();
    const config = {
      getOrThrow: () => ({
        windowSeconds: 60,
        maxRequests: 120,
        public: {
          enabled: true,
          maxRequests: GLOBAL_LIMIT,
          windowSeconds: 60,
          trustProxy: true,
          clientIdentifiers: ['apiKey'],
        },
      }),
      get: () => ({ apiPrefix: 'api/v1' }),
    };

    const moduleRef = await Test.createTestingModule({
      controllers: [AuthController, PublicCatalogController, AgentsController],
      providers: [
        { provide: ConfigService, useValue: config },
        { provide: REDIS_CLIENT, useValue: redis },
        { provide: APP_GUARD, useClass: PublicRateLimitGuard },
        { provide: APP_FILTER, useClass: AllExceptionsFilter },
      ],
    }).compile();

    app = moduleRef.createNestApplication({ logger: false });
    app.setGlobalPrefix('api/v1');
    await app.listen(0, '127.0.0.1');
    baseUrl = `${await app.getUrl()}/api/v1`;
  });

  afterAll(async () => {
    await app.close();
  });

  const send = (path: string, ip: string, method = 'GET', apiKey?: string) =>
    fetch(`${baseUrl}${path}`, {
      method,
      headers: {
        'x-forwarded-for': ip,
        ...(apiKey ? { 'x-api-key': apiKey } : {}),
      },
    });

  it('serves a burst up to the global limit, then answers 429 with standard headers', async () => {
    const ip = '198.51.100.110';
    const statuses: number[] = [];
    const remaining: (string | null)[] = [];
    for (let i = 0; i < GLOBAL_LIMIT; i++) {
      const res = await send('/auth/login', ip, 'POST');
      statuses.push(res.status);
      remaining.push(res.headers.get('x-ratelimit-remaining'));
    }

    expect(statuses).toEqual(Array(GLOBAL_LIMIT).fill(201));
    expect(remaining).toEqual(['3', '2', '1', '0']);

    const limited = await send('/auth/login', ip, 'POST');

    expect(limited.status).toBe(429);
    expect(limited.headers.get('x-ratelimit-limit')).toBe(String(GLOBAL_LIMIT));
    expect(limited.headers.get('x-ratelimit-remaining')).toBe('0');
    const reset = Number(limited.headers.get('x-ratelimit-reset'));
    const nowSeconds = Math.floor(Date.now() / 1000);
    expect(reset).toBeGreaterThanOrEqual(nowSeconds);
    expect(reset).toBeLessThanOrEqual(nowSeconds + 61);
    expect(Number(limited.headers.get('retry-after'))).toBeGreaterThanOrEqual(1);
  });

  it('enforces the per-route @PublicRateLimit() budget on heavier endpoints', async () => {
    const ip = '198.51.100.120';

    expect((await send('/public/search', ip)).status).toBe(200);
    expect((await send('/public/search', ip)).status).toBe(200);

    const limited = await send('/public/search', ip);
    expect(limited.status).toBe(429);
    expect(limited.headers.get('x-ratelimit-limit')).toBe('2');
    expect(limited.headers.get('x-ratelimit-remaining')).toBe('0');

    // The global-limit route of the same controller is unaffected.
    expect((await send('/public/status', ip)).status).toBe(200);
  });

  it('tracks API-key clients separately from other callers behind the same IP', async () => {
    const ip = '198.51.100.130';

    for (let i = 0; i < GLOBAL_LIMIT; i++) {
      await send('/public/status', ip, 'GET', 'ak_live_integration');
    }
    const limited = await send('/public/status', ip, 'GET', 'ak_live_integration');
    expect(limited.status).toBe(429);

    // A different key (and a keyless caller) on the same IP still has budget.
    expect((await send('/public/status', ip, 'GET', 'ak_live_other')).status).toBe(200);
    expect((await send('/public/status', ip)).status).toBe(200);
  });

  it('keeps other IPs unaffected while one IP is limited', async () => {
    for (let i = 0; i <= GLOBAL_LIMIT; i++) {
      await send('/public/status', '198.51.100.140');
    }

    const other = await send('/public/status', '198.51.100.141');
    expect(other.status).toBe(200);
    expect(other.headers.get('x-ratelimit-remaining')).toBe(String(GLOBAL_LIMIT - 1));
  });

  it('never limits or annotates authenticated routes', async () => {
    const ip = '198.51.100.150';
    for (let i = 0; i < GLOBAL_LIMIT * 2; i++) {
      const res = await send('/agents', ip);
      expect(res.status).toBe(200);
      expect(res.headers.get('x-ratelimit-limit')).toBeNull();
    }
  });
});
