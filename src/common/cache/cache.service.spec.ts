import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Logger } from '@nestjs/common';
import { CacheService } from './cache.service';

describe('CacheService', () => {
  let redis: {
    get: ReturnType<typeof vi.fn>;
    set: ReturnType<typeof vi.fn>;
    del: ReturnType<typeof vi.fn>;
    scan: ReturnType<typeof vi.fn>;
  };

  beforeEach(() => {
    vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
    redis = {
      get: vi.fn().mockResolvedValue(null),
      set: vi.fn().mockResolvedValue('OK'),
      del: vi.fn().mockResolvedValue(1),
      scan: vi.fn().mockResolvedValue(['0', []]),
    };
  });

  it('round-trips a value through the namespaced key with a TTL', async () => {
    const cache = new CacheService(redis as never);
    redis.get.mockResolvedValue(
      JSON.stringify({ value: { revoked: false }, cachedAt: 1, expiresAt: 2 }),
    );

    await cache.set('ns', 'k', { revoked: false }, 30);

    expect(redis.set).toHaveBeenCalledWith(
      'ns:k',
      expect.stringContaining('"revoked":false'),
      'EX',
      30,
    );
    await expect(cache.get<{ revoked: boolean }>('ns', 'k')).resolves.toEqual({ revoked: false });
  });

  it('returns null on miss and never throws when Redis fails', async () => {
    const cache = new CacheService(redis as never);

    await expect(cache.get('ns', 'missing')).resolves.toBeNull();

    redis.get.mockRejectedValue(new Error('READONLY'));
    await expect(cache.get('ns', 'k')).resolves.toBeNull();
    expect(Logger.prototype.warn).toHaveBeenCalled();
  });

  it('set swallows Redis failures instead of breaking the request path', async () => {
    const cache = new CacheService(redis as never);
    redis.set.mockRejectedValue(new Error('connection refused'));

    await expect(cache.set('ns', 'k', 'v', 30)).resolves.toBeUndefined();
  });

  it('getWithMeta rejects entries older than the requested max age', async () => {
    const cache = new CacheService(redis as never);
    const fresh = { value: 'fresh', cachedAt: Date.now() - 1_000, expiresAt: Date.now() + 60_000 };
    const stale = { value: 'stale', cachedAt: Date.now() - 10_000, expiresAt: Date.now() + 60_000 };
    redis.get.mockResolvedValue(JSON.stringify(fresh));

    await expect(cache.getWithMeta('ns', 'k', 5_000)).resolves.toMatchObject({ value: 'fresh' });

    redis.get.mockResolvedValue(JSON.stringify(stale));
    await expect(cache.getWithMeta('ns', 'k', 5_000)).resolves.toBeNull();
  });

  it('getWithMeta returns null when the entry itself has expired', async () => {
    const cache = new CacheService(redis as never);
    redis.get.mockResolvedValue(
      JSON.stringify({ value: 'old', cachedAt: Date.now() - 9_000, expiresAt: Date.now() - 1_000 }),
    );

    await expect(cache.getWithMeta('ns', 'k')).resolves.toBeNull();
  });

  it('del removes the namespaced key', async () => {
    const cache = new CacheService(redis as never);

    await cache.del('ns', 'k');

    expect(redis.del).toHaveBeenCalledWith('ns:k');
  });

  it('delByPrefix deletes every matching key in batches', async () => {
    const cache = new CacheService(redis as never);
    redis.scan
      .mockResolvedValueOnce(['123', ['ns:a', 'ns:b']])
      .mockResolvedValueOnce(['0', ['ns:c']]);

    await cache.delByPrefix('ns', '');

    expect(redis.del).toHaveBeenCalledWith('ns:a', 'ns:b');
    expect(redis.del).toHaveBeenCalledWith('ns:c');
  });

  it('is a no-op when no Redis client is available', async () => {
    const cache = new CacheService(null);

    await expect(cache.get('ns', 'k')).resolves.toBeNull();
    await expect(cache.set('ns', 'k', 'v', 30)).resolves.toBeUndefined();
    await expect(cache.del('ns', 'k')).resolves.toBeUndefined();
    expect(redis.set).not.toHaveBeenCalled();
  });
});
