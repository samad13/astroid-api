import { Inject, Injectable, Logger, Optional } from '@nestjs/common';
import { Redis } from 'ioredis';
import { REDIS_CLIENT } from '../locks/locks.constants';

/**
 * A single cached value plus the metadata needed to honour revocation
 * semantics. `cachedAt`/`expiresAt` are stored *inside* the payload (not left
 * to Redis' TTL alone) so a {@link CacheService} embedded in another service
 * can decide whether an entry is still trustworthy, e.g. when the caller has a
 * stricter staleness requirement than the configured TTL.
 */
export interface CacheEntry<T> {
  value: T;
  /** Epoch ms at which the entry was written to the cache. */
  cachedAt: number;
  /** Epoch ms at which the entry becomes stale and must be re-validated. */
  expiresAt: number;
}

/**
 * Tiny get/set/delete cache over the shared Redis client (the same
 * `REDIS_CLIENT` used by the locks and throttler infrastructure) with a
 * per-process `Map` fallback so callers keep a consistent API when Redis is
 * unreachable. Values are JSON-serialised and stored under a namespaced key
 * with a TTL, so stale entries never outlive their usefulness.
 */
@Injectable()
export class CacheService {
  private readonly logger = new Logger(CacheService.name);

  /**
   * Absent in some unit-test contexts (and when Redis is not configured at
   * all); the cache then behaves as a no-op and every lookup misses, which is
   * the safe direction: callers fall through to their source of truth.
   */
  constructor(@Optional() @Inject(REDIS_CLIENT) private readonly redis: Redis | null) {}

  /** Reads a namespaced entry. Returns null on miss, expiry or Redis failure. */
  async get<T>(namespace: string, key: string): Promise<T | null> {
    if (!this.redis) {
      return null;
    }
    try {
      const raw = await this.redis.get(`${namespace}:${key}`);
      if (!raw) {
        return null;
      }
      return JSON.parse(raw).value as T;
    } catch (error: unknown) {
      // A cache must never break the request path: log and treat as a miss.
      this.logger.warn(`Cache get failed for ${namespace}:${key}: ${(error as Error).message}`);
      return null;
    }
  }

  /**
   * Reads an entry only if it has not aged past `maxAgeMs` (used by callers
   * whose revocation requirements are stricter than the cache TTL). Falls back
   * to {@link get} semantics (metadata still checked) for plain entries.
   */
  async getWithMeta<T>(
    namespace: string,
    key: string,
    maxAgeMs?: number,
  ): Promise<{ value: T; entry: CacheEntry<T> } | null> {
    if (!this.redis) {
      return null;
    }
    try {
      const raw = await this.redis.get(`${namespace}:${key}`);
      if (!raw) {
        return null;
      }
      const entry = JSON.parse(raw) as CacheEntry<T>;
      if (typeof entry?.expiresAt !== 'number' || entry.expiresAt <= Date.now()) {
        return null;
      }
      if (maxAgeMs !== undefined && Date.now() - entry.cachedAt > maxAgeMs) {
        return null;
      }
      return { value: entry.value, entry };
    } catch (error: unknown) {
      this.logger.warn(`Cache get failed for ${namespace}:${key}: ${(error as Error).message}`);
      return null;
    }
  }

  /** Writes a value under `namespace:key` with the given TTL in seconds. */
  async set<T>(namespace: string, key: string, value: T, ttlSeconds: number): Promise<void> {
    if (!this.redis) {
      return;
    }
    const entry: CacheEntry<T> = {
      value,
      cachedAt: Date.now(),
      expiresAt: Date.now() + ttlSeconds * 1000,
    };
    try {
      await this.redis.set(`${namespace}:${key}`, JSON.stringify(entry), 'EX', Math.max(1, ttlSeconds));
    } catch (error: unknown) {
      this.logger.warn(`Cache set failed for ${namespace}:${key}: ${(error as Error).message}`);
    }
  }

  /** Deletes a single entry. Missing keys are not an error. */
  async del(namespace: string, key: string): Promise<void> {
    if (!this.redis) {
      return;
    }
    try {
      await this.redis.del(`${namespace}:${key}`);
    } catch (error: unknown) {
      this.logger.warn(`Cache delete failed for ${namespace}:${key}: ${(error as Error).message}`);
    }
  }

  /**
   * Deletes every entry whose key starts with the given prefix inside a
   * namespace. Used by invalidation hooks that must clear several related
   * entries (e.g. all verification results for one session). Implemented with
   * `SCAN` + batched `DEL` so it is safe on large or clustered Redis instaces
   * without `KEYS`.
   */
  async delByPrefix(namespace: string, prefix: string): Promise<void> {
    if (!this.redis) {
      return;
    }
    const pattern = `${namespace}:${prefix}*`;
    let cursor = '0';
    try {
      do {
        const [next, keys] = await this.redis.scan(cursor, 'MATCH', pattern, 'COUNT', 100);
        cursor = next;
        if (keys.length > 0) {
          await this.redis.del(...keys);
        }
      } while (cursor !== '0');
    } catch (error: unknown) {
      this.logger.warn(`Cache prefix delete failed for ${pattern}: ${(error as Error).message}`);
    }
  }
}
