import { beforeEach, describe, expect, it, vi } from 'vitest';
import { TokenVerificationCacheService } from '../services/token-verification-cache.service';
import { CacheService } from '../../../common/cache/cache.service';

describe('TokenVerificationCacheService', () => {
  let service: TokenVerificationCacheService;
  let cache: {
    get: ReturnType<typeof vi.fn>;
    set: ReturnType<typeof vi.fn>;
    del: ReturnType<typeof vi.fn>;
    delByPrefix: ReturnType<typeof vi.fn>;
  };

  beforeEach(() => {
    cache = {
      get: vi.fn().mockResolvedValue(null),
      set: vi.fn().mockResolvedValue(undefined),
      del: vi.fn().mockResolvedValue(undefined),
      delByPrefix: vi.fn().mockResolvedValue(undefined),
    };
    service = new TokenVerificationCacheService(cache as unknown as CacheService, {
      get: vi.fn().mockReturnValue(30),
    } as never);
  });

  describe('getSessionRevocation / setSessionRevocation', () => {
    it('returns null when nothing is cached', async () => {
      await expect(service.getSessionRevocation('session-1')).resolves.toBeNull();
      expect(cache.get).toHaveBeenCalledWith('auth:token-verification', 'session-1');
    });

    it('returns the cached answer on hit', async () => {
      cache.get.mockResolvedValue({ revoked: true, verifiedAt: 123 });

      await expect(service.getSessionRevocation('session-1')).resolves.toEqual({
        revoked: true,
        verifiedAt: 123,
      });
    });

    it('stores the answer under the session key with the configured TTL', async () => {
      await service.setSessionRevocation('session-1', { revoked: false, verifiedAt: 42 });

      expect(cache.set).toHaveBeenCalledWith(
        'auth:token-verification',
        'session-1',
        { revoked: false, verifiedAt: 42 },
        30,
      );
    });

    it('ignores empty session ids without touching the cache', async () => {
      await expect(service.getSessionRevocation('')).resolves.toBeNull();
      await service.setSessionRevocation('', { revoked: false, verifiedAt: 1 });
      expect(cache.get).not.toHaveBeenCalledWith('auth:token-verification', '');
      expect(cache.set).not.toHaveBeenCalled();
    });

    it('treats malformed cache payloads as a miss', async () => {
      cache.get.mockResolvedValue({ garbage: true });

      await expect(service.getSessionRevocation('session-1')).resolves.toBeNull();
    });
  });

  describe('resolveSessionRevocation', () => {
    it('answers from the cache without invoking the resolver (cache hit)', async () => {
      cache.get.mockResolvedValue({ revoked: false, verifiedAt: Date.now() });
      const resolve = vi.fn().mockResolvedValue(true);

      const result = await service.resolveSessionRevocation('session-1', resolve);

      expect(result).toMatchObject({ revoked: false });
      expect(resolve).not.toHaveBeenCalled();
    });

    it('falls back to the resolver on a miss and caches the fresh answer', async () => {
      const resolve = vi.fn().mockResolvedValue(false);

      const result = await service.resolveSessionRevocation('session-1', resolve);

      expect(result.revoked).toBe(false);
      expect(resolve).toHaveBeenCalledTimes(1);
      expect(cache.set).toHaveBeenCalledWith(
        'auth:token-verification',
        'session-1',
        expect.objectContaining({ revoked: false }),
        30,
      );
    });

    it('propagates resolver failures so callers keep their fail-open behavior', async () => {
      const resolve = vi.fn().mockRejectedValue(new Error('Redis down'));

      await expect(
        service.resolveSessionRevocation('session-1', resolve),
      ).rejects.toThrow('Redis down');
      expect(cache.set).not.toHaveBeenCalled();
    });
  });

  describe('invalidation hooks', () => {
    it('invalidateSessionRevocation drops the cached entry', async () => {
      await service.invalidateSessionRevocation('session-1');

      expect(cache.del).toHaveBeenCalledWith('auth:token-verification', 'session-1');
    });

    it('invalidateOnRefreshRotation invalidates the rotated (old) session', async () => {
      await service.invalidateOnRefreshRotation('old-session');

      expect(cache.del).toHaveBeenCalledWith('auth:token-verification', 'old-session');
    });

    it('a session revoked after being cached is observed as revoked again', async () => {
      // 1. First verification caches "not revoked".
      const resolve = vi.fn().mockResolvedValueOnce(false);
      await service.resolveSessionRevocation('session-1', resolve);
      // 2. Logout invalidates the cached answer...
      await service.invalidateSessionRevocation('session-1');
      // 3. ...so the next verification consults the source of truth again.
      cache.get.mockResolvedValue(null);
      const resolveAfterRevocation = vi.fn().mockResolvedValue(true);
      const result = await service.resolveSessionRevocation('session-1', resolveAfterRevocation);

      expect(result.revoked).toBe(true);
      expect(resolveAfterRevocation).toHaveBeenCalledTimes(1);
    });
  });

  it('clearAll drops every cached verification entry', async () => {
    await service.clearAll();
    expect(cache.delByPrefix).toHaveBeenCalledWith('auth:token-verification', '');
  });

  it('falls back to the 30s default TTL when TOKEN_CACHE_TTL is unset', () => {
    const fallback = new TokenVerificationCacheService(cache as unknown as CacheService, {
      get: vi.fn().mockReturnValue(undefined),
    } as never);
    expect(fallback.cacheTtlSeconds).toBe(30);
  });
});
