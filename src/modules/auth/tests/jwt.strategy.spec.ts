import { describe, it, expect, beforeEach, vi } from 'vitest';
import { JwtStrategy } from '../jwt.strategy';
import { TokenBlacklistService } from '../services/token-blacklist.service';
import { TokenVerificationCacheService } from '../services/token-verification-cache.service';
import { AuthConfig } from '../../../config/auth.config';
import { JwtAccessPayload } from '../../../common/interfaces/authenticated-user.interface';

const authConfig: AuthConfig = {
  accessSecret: 'access-secret-at-least-sixteen-chars',
  refreshSecret: 'refresh-secret-at-least-sixteen-chars',
  accessTtl: 900,
  refreshTtl: 1209600,
  passkey: { rpId: 'localhost', rpName: 'Astroid', origin: 'http://localhost:3001' },
};

const mockConfig = {
  getOrThrow: vi.fn().mockReturnValue(authConfig),
};

const payload: JwtAccessPayload = {
  sub: 'user-1',
  organizationId: 'org-1',
  email: 'ada@acme.com',
  role: 'OWNER',
  sessionId: 'session-123',
};

function makeStrategy(
  blacklist: Partial<TokenBlacklistService>,
  verificationCache: Partial<TokenVerificationCacheService>,
) {
  return new JwtStrategy(
    mockConfig as never,
    blacklist as TokenBlacklistService,
    verificationCache as TokenVerificationCacheService,
  );
}

describe('JwtStrategy', () => {
  let tokenBlacklist: { isAccessTokenRevoked: ReturnType<typeof vi.fn> };
  let verificationCache: {
    resolveSessionRevocation: ReturnType<typeof vi.fn>;
  };

  beforeEach(() => {
    vi.clearAllMocks();
    tokenBlacklist = { isAccessTokenRevoked: vi.fn().mockResolvedValue(false) };
    verificationCache = {
      resolveSessionRevocation: vi.fn().mockImplementation(
        (sessionId: string, resolve: () => Promise<boolean>) =>
          resolve().then((revoked) => ({ revoked, verifiedAt: Date.now() })),
      ),
    };
  });

  it('rejects a valid-signature token whose session is blacklisted', async () => {
    tokenBlacklist.isAccessTokenRevoked.mockResolvedValue(true);
    const strategy = makeStrategy(tokenBlacklist, verificationCache);

    await expect(strategy.validate(payload)).rejects.toThrow('Session has been revoked');
    expect(tokenBlacklist.isAccessTokenRevoked).toHaveBeenCalledWith('session-123');
  });

  it('grants access to a token whose session is not blacklisted', async () => {
    const strategy = makeStrategy(tokenBlacklist, verificationCache);

    await expect(strategy.validate(payload)).resolves.toMatchObject({
      id: 'user-1',
      sessionId: 'session-123',
    });
  });

  it('serves repeated verifications from the cache without re-querying the blacklist', async () => {
    // The cache answers every check: the blacklist is never consulted.
    verificationCache.resolveSessionRevocation.mockResolvedValue({
      revoked: false,
      verifiedAt: Date.now(),
    });
    const strategy = makeStrategy(tokenBlacklist, verificationCache);

    for (let i = 0; i < 3; i++) {
      await expect(strategy.validate(payload)).resolves.toMatchObject({ id: 'user-1' });
    }

    expect(tokenBlacklist.isAccessTokenRevoked).not.toHaveBeenCalled();
  });

  it('fails open and grants access when Redis is unreachable', async () => {
    verificationCache.resolveSessionRevocation.mockRejectedValue(new Error('Redis down'));
    const strategy = makeStrategy(tokenBlacklist, verificationCache);

    await expect(strategy.validate(payload)).resolves.toMatchObject({
      id: 'user-1',
    });
  });

  it('rejects a malformed token missing the subject', async () => {
    const strategy = makeStrategy(tokenBlacklist, verificationCache);

    await expect(
      strategy.validate({ organizationId: 'org-1', email: 'a@b.c', role: 'OWNER' } as never),
    ).rejects.toThrow('Malformed access token');
  });

  it('skips the revocation check for tokens without a session id', async () => {
    const strategy = makeStrategy(tokenBlacklist, verificationCache);
    const payloadWithoutSession: JwtAccessPayload = {
      sub: 'user-1',
      organizationId: 'org-1',
      email: 'ada@acme.com',
      role: 'OWNER',
    };

    await expect(strategy.validate(payloadWithoutSession)).resolves.toMatchObject({ id: 'user-1' });
    expect(verificationCache.resolveSessionRevocation).not.toHaveBeenCalled();
  });
});
