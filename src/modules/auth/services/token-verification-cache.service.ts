import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { CacheService } from '../../../common/cache/cache.service';

/**
 * Result of verifying a session against the revocation store. `revoked` is the
 * authoritative answer (true when the session has been blacklisted by logout
 * or credential rotation); `verifiedAt` records when the check happened so the
 * cache can bound how long the answer is trusted.
 */
export interface SessionRevocationResult {
  revoked: boolean;
  verifiedAt: number;
}

/**
 * Cache in front of the token revocation store ({@link TokenBlacklistService}
 * — itself Redis-backed). Every authenticated request asks "is this session
 * still revoked?", which is one Redis round trip per request; this service
 * answers it from a short-lived cache entry instead, cutting Redis load by
 * roughly the number of requests a session makes per TTL window.
 *
 * Revocation stays reliable because every cache entry is bounded by
 * `cacheTtlSeconds` (default 30s, `TOKEN_CACHE_TTL`), which is deliberately
 * shorter than the shortest credential lifetime (the 15-minute access token),
 * and because every revocation / logout / refresh-rotation path calls the
 * {@link invalidate} hooks, which drop the cached answer immediately. A cached
 * "not revoked" answer therefore survives at most one TTL window — the same
 * bounded staleness the project already accepts for the Redis blacklist
 * itself — and explicit revocations take effect at once.
 *
 * Key layout: `auth:token-verification:<sessionId>` — one entry per session,
 * invalidated in O(1) on logout without any scan.
 */
@Injectable()
export class TokenVerificationCacheService {
  private static readonly NAMESPACE = 'auth:token-verification';
  private readonly ttlSeconds: number;

  constructor(
    private readonly cache: CacheService,
    config: ConfigService,
  ) {
    // Optional tuning knob; follows the BalanceCacheService pattern of an
    // unvalidated, defaulted variable read straight from ConfigService. The
    // 30s default stays well below the shortest token lifetime (access TTL).
    const configured = config.get<number>('TOKEN_CACHE_TTL', 30);
    this.ttlSeconds = typeof configured === 'number' && configured > 0 ? configured : 30;
  }

  /** Returns the cached revocation answer for a session, or null on miss. */
  async getSessionRevocation(sessionId: string): Promise<SessionRevocationResult | null> {
    if (!sessionId) {
      return null;
    }
    const hit = await this.cache.get<SessionRevocationResult>(this.namespace(), this.key(sessionId));
    if (!hit || typeof hit.revoked !== 'boolean') {
      return null;
    }
    return hit;
  }

  /** Caches a revocation answer for one TTL window. */
  async setSessionRevocation(sessionId: string, result: SessionRevocationResult): Promise<void> {
    if (!sessionId) {
      return;
    }
    await this.cache.set(this.namespace(), this.key(sessionId), result, this.ttlSeconds);
  }

  /**
   * Cache-read / source-of-truth / cache-write helper. `resolve` must perform
   * the authoritative check (Redis blacklist); its answer is cached for the
   * next requests within the TTL window.
   */
  async resolveSessionRevocation(
    sessionId: string,
    resolve: () => Promise<boolean>,
  ): Promise<SessionRevocationResult> {
    const cached = await this.getSessionRevocation(sessionId);
    if (cached) {
      return cached;
    }
    const result: SessionRevocationResult = { revoked: await resolve(), verifiedAt: Date.now() };
    await this.setSessionRevocation(sessionId, result);
    return result;
  }

  /**
   * Invalidation hook: the session's access token has been revoked (logout or
   * credential rotation). Drops the cached answer so the next verification
   * hits the source of truth and observes the revocation immediately.
   */
  async invalidateSessionRevocation(sessionId: string): Promise<void> {
    await this.cache.del(this.namespace(), this.key(sessionId));
  }

  /**
   * Invalidation hook for refresh flows: a rotated refresh token means the old
   * session is dead and a new one was born, but the old session's access token
   * is still in flight, so its cached "not revoked" answer must be dropped.
   */
  async invalidateOnRefreshRotation(oldSessionId: string): Promise<void> {
    await this.invalidateSessionRevocation(oldSessionId);
  }

  /**
   * Diagnostics hook: clears every cached verification entry. Intended for
   * tests and emergency cache flushes, not for the request path (the SCAN it
   * performs is not O(1)).
   */
  async clearAll(): Promise<void> {
    await this.cache.delByPrefix(this.namespace(), '');
  }

  /** Configured TTL, exposed for tests and configuration assertions. */
  get cacheTtlSeconds(): number {
    return this.ttlSeconds;
  }

  private namespace(): string {
    return TokenVerificationCacheService.NAMESPACE;
  }

  private key(sessionId: string): string {
    return sessionId;
  }
}
