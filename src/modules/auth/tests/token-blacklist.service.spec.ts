import { describe, it, expect, beforeEach, vi } from 'vitest';
import { TokenBlacklistService } from '../services/token-blacklist.service';
import { TokenVerificationCacheService } from '../services/token-verification-cache.service';

describe('TokenBlacklistService', () => {
  let service: TokenBlacklistService;
  let verificationCache: {
    invalidateSessionRevocation: ReturnType<typeof vi.fn>;
  };
  let redis: {
    set: ReturnType<typeof vi.fn>;
    exists: ReturnType<typeof vi.fn>;
  };

  beforeEach(() => {
    redis = {
      set: vi.fn().mockResolvedValue('OK'),
      exists: vi.fn().mockResolvedValue(0),
    };
    verificationCache = {
      invalidateSessionRevocation: vi.fn().mockResolvedValue(undefined),
    };
    service = new TokenBlacklistService(
      redis as never,
      verificationCache as unknown as TokenVerificationCacheService,
    );
  });

  it('revokes access and refresh tokens with distinct TTLs', async () => {
    await service.revokeSession('session-1', 900, 1209600);

    expect(redis.set).toHaveBeenCalledWith(
      'auth:blacklist:access:session-1',
      '1',
      'EX',
      900,
    );
    expect(redis.set).toHaveBeenCalledWith(
      'auth:blacklist:refresh:session-1',
      '1',
      'EX',
      1209600,
    );
  });

  it('decorates the blacklist with the correct key and TTL for an access token', async () => {
    await service.revokeAccessToken('session-1', 900);
    expect(redis.set).toHaveBeenCalledWith('auth:blacklist:access:session-1', '1', 'EX', 900);
  });

  it('isAccessTokenRevoked returns true when the key exists', async () => {
    redis.exists.mockResolvedValue(1);
    await expect(service.isAccessTokenRevoked('session-1')).resolves.toBe(true);
    expect(redis.exists).toHaveBeenCalledWith('auth:blacklist:access:session-1');
  });

  it('isAccessTokenRevoked returns false when the key is absent', async () => {
    await expect(service.isAccessTokenRevoked('session-1')).resolves.toBe(false);
  });

  it('isRefreshTokenRevoked checks the refresh key', async () => {
    redis.exists.mockResolvedValue(1);
    await expect(service.isRefreshTokenRevoked('session-1')).resolves.toBe(true);
    expect(redis.exists).toHaveBeenCalledWith('auth:blacklist:refresh:session-1');
  });

  it('treats an empty session id as not revoked', async () => {
    await expect(service.isAccessTokenRevoked('')).resolves.toBe(false);
    expect(redis.exists).not.toHaveBeenCalled();
  });

  it('lets logout succeed when Redis is unreachable', async () => {
    redis.set.mockRejectedValue(new Error('Redis connection failed'));
    await expect(
      service.revokeSession('session-1', 900, 1209600),
    ).resolves.toBeUndefined();
  });

  it('invalidates the cached verification answer on every revocation path', async () => {
    await service.revokeSession('session-1', 900, 1209600);
    await service.revokeAccessToken('session-2', 900);
    await service.revokeRefreshToken('session-3', 1209600);

    // revokeSession invalidates once per token kind (access + refresh).
    expect(verificationCache.invalidateSessionRevocation.mock.calls.filter(([id]) => id === 'session-1')).toHaveLength(2);
    expect(verificationCache.invalidateSessionRevocation).toHaveBeenCalledWith('session-2');
    expect(verificationCache.invalidateSessionRevocation).toHaveBeenCalledWith('session-3');
  });

  it('still invalidates the cache when blacklisting fails on a Redis outage', async () => {
    redis.set.mockRejectedValue(new Error('Redis connection failed'));

    await service.revokeSession('session-1', 900, 1209600);

    expect(verificationCache.invalidateSessionRevocation).toHaveBeenCalledWith('session-1');
  });
});