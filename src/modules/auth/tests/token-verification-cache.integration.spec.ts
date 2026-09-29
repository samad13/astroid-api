import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Controller, Get, INestApplication, UseGuards } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { PassportModule } from '@nestjs/passport';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { JwtAuthGuard } from '../../../common/guards/jwt-auth.guard';
import { CurrentUser } from '../../../common/decorators/current-user.decorator';
import { AuthenticatedUser } from '../../../common/interfaces/authenticated-user.interface';
import { JwtStrategy } from '../jwt.strategy';
import { TokenBlacklistService } from '../services/token-blacklist.service';
import { TokenVerificationCacheService } from '../services/token-verification-cache.service';
import { CacheService } from '../../../common/cache/cache.service';
import { REDIS_CLIENT } from '../../../common/locks/locks.constants';

/**
 * Exercises the authenticated-request path end to end: a signed JWT flows
 * through the global `JwtAuthGuard` into `JwtStrategy`, which consults the
 * token verification cache in front of the Redis blacklist. The Redis client
 * is a stand-in implementing only the primitives the stack touches
 * (`get`/`set`/`del` for cache and blacklist keys), letting the test count
 * exactly how many revocation lookups happen per request.
 */

const ACCESS_SECRET = 'test-access-secret-at-least-32-chars';

@Controller('protected')
@UseGuards(JwtAuthGuard)
class ProtectedController {
  @Get('me')
  me(@CurrentUser() user: AuthenticatedUser) {
    return { id: user.id, organizationId: user.organizationId };
  }
}

describe('Token verification caching (integration)', () => {
  let app: INestApplication;
  let jwt: JwtService;
  let blacklist: { isAccessTokenRevoked: ReturnType<typeof vi.fn> };
  let redisStore: Map<string, string>;
  let blacklistLookups: number;

  /** Minimal Redis stand-in: real GET/SET/DEL semantics over a Map. */
  const fakeRedis = {
    get: vi.fn(async (key: string) => redisStore.get(key) ?? null),
    set: vi.fn(async (key: string, value: string) => {
      redisStore.set(key, value);
      return 'OK';
    }),
    del: vi.fn(async (...keys: string[]) => {
      let removed = 0;
      for (const key of keys) {
        if (redisStore.delete(key)) removed++;
      }
      return removed;
    }),
    exists: vi.fn(async (key: string) => (redisStore.has(key) ? 1 : 0)),
  };

  const signAccessToken = async (sessionId: string) =>
    jwt.signAsync(
      { sub: 'user-1', organizationId: 'org-1', email: 'ada@acme.com', role: 'OWNER', sessionId },
      { secret: ACCESS_SECRET, expiresIn: 900 },
    );

  /** Revokes a session the same way the logout path does (blacklist + cache invalidation). */
  const revokeSession = async (sessionId: string) => {
    redisStore.set(`auth:blacklist:access:${sessionId}`, '1');
    await app.get(TokenVerificationCacheService).invalidateSessionRevocation(sessionId);
  };

  beforeEach(async () => {
    redisStore = new Map();
    blacklistLookups = 0;

    blacklist = {
      isAccessTokenRevoked: vi.fn().mockImplementation(async (sessionId: string) => {
        blacklistLookups += 1;
        return redisStore.has(`auth:blacklist:access:${sessionId}`);
      }),
    };

    const moduleRef = await Test.createTestingModule({
      imports: [PassportModule.register({ defaultStrategy: 'jwt' }), JwtModule.register({})],
      controllers: [ProtectedController],
      providers: [
        {
          provide: ConfigService,
          useValue: {
            getOrThrow: () => ({ accessSecret: ACCESS_SECRET }),
            get: () => undefined,
          },
        },
        { provide: REDIS_CLIENT, useValue: fakeRedis },
        CacheService,
        TokenVerificationCacheService,
        { provide: TokenBlacklistService, useValue: blacklist },
        JwtStrategy,
        JwtAuthGuard,
      ],
    }).compile();

    app = moduleRef.createNestApplication({ logger: false });
    await app.init();
    jwt = app.get(JwtService);
  });

  const authenticate = async (token: string): Promise<number> => {
    // canActivate is invoked through the guard pipeline exactly as production
    // wiring does; we drive it directly to observe pass/fail without HTTP.
    const request = { headers: { authorization: `Bearer ${token}` } };
    const guard = app.get(JwtAuthGuard);
    const passportFlow = guard.canActivate({
      switchToHttp: () => ({
        getRequest: () => request,
        getResponse: () => ({}),
      }),
      getHandler: () => ProtectedController.prototype.me,
      getClass: () => ProtectedController,
    } as never);
    try {
      const result = await passportFlow;
      return result === true ? 200 : 401;
    } catch {
      return 401;
    }
  };

  it('caches the first verification and serves later requests without blacklist lookups', async () => {
    const token = await signAccessToken('session-cache');
    expect(await authenticate(token)).toBe(200);
    expect(blacklistLookups).toBe(1);

    // Subsequent requests hit the cache: no additional blacklist queries.
    expect(await authenticate(token)).toBe(200);
    expect(await authenticate(token)).toBe(200);
    expect(blacklistLookups).toBe(1);
  });

  it('observes a revocation immediately because logout invalidates the cache', async () => {
    const token = await signAccessToken('session-revoked');
    expect(await authenticate(token)).toBe(200);
    expect(blacklistLookups).toBe(1);

    // Logout path: blacklist write + cache invalidation, as wired in
    // AuthService via TokenBlacklistService.
    await revokeSession('session-revoked');
    expect(await authenticate(token)).toBe(401);
  });

  it('treats a cache miss by consulting the blacklist and re-populating the cache', async () => {
    const token = await signAccessToken('session-miss');
    expect(await authenticate(token)).toBe(200);
    expect(blacklistLookups).toBe(1);

    // Invalidate (cache miss on the next request), then verify the answer is
    // re-derived from the source of truth and cached again.
    await app.get(TokenVerificationCacheService).invalidateSessionRevocation('session-miss');
    redisStore.set('auth:blacklist:access:session-miss', '1');
    expect(await authenticate(token)).toBe(401);
    expect(blacklistLookups).toBe(2);

    // The fresh "revoked" answer is now cached — no further lookups.
    redisStore.delete('auth:blacklist:access:session-miss');
    expect(await authenticate(token)).toBe(401);
    expect(blacklistLookups).toBe(2);
  });

  it('keeps independent sessions isolated (no cross-session cache leakage)', async () => {
    const tokenA = await signAccessToken('session-A');
    const tokenB = await signAccessToken('session-B');

    expect(await authenticate(tokenA)).toBe(200);
    expect(blacklistLookups).toBe(1);

    // Revoking session B must not affect session A's cached answer.
    await revokeSession('session-B');
    expect(await authenticate(tokenA)).toBe(200);
    expect(blacklistLookups).toBe(1);
  });
});
