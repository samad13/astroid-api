import { Injectable, Logger } from '@nestjs/common';
import { Redis } from 'ioredis';
import { TokenVerificationCacheService } from './token-verification-cache.service';

/**
 * Redis-backed token revocation store. Issued JWTs remain valid until their
 * natural expiration, so logging out or rotating credentials must proactively
 * mark the offending tokens as revoked. Each session id is stored under a
 * short-lived Redis key whose TTL matches the remaining token lifetime; once
 * the key expires, the token would have expired anyway and is dropped.
 *
 * Access and refresh tokens are tracked under separate keys so their (much
 * different) lifetimes can be enforced independently.
 *
 * Every revocation also invalidates the session's entry in the token
 * verification cache ({@link TokenVerificationCacheService}), so a cached
 * "not revoked" answer can never outlive the revocation itself.
 */
@Injectable()
export class TokenBlacklistService {
  private readonly logger = new Logger(TokenBlacklistService.name);

  constructor(
    private readonly redis: Redis,
    private readonly verificationCache: TokenVerificationCacheService,
  ) {}

  /** Marks every token tied to a session as revoked. */
  async revokeSession(
    sessionId: string,
    accessTtlSeconds: number,
    refreshTtlSeconds: number,
  ): Promise<void> {
    try {
      await Promise.all([
        this.revokeAccessToken(sessionId, accessTtlSeconds),
        this.revokeRefreshToken(sessionId, refreshTtlSeconds),
      ]);
    } catch (error: unknown) {
      // Never let a Redis outage prevent logout from succeeding.
      this.logger.warn(`Failed to blacklist session ${sessionId}: ${(error as Error).message}`);
      // A failed blacklist write may have left a stale "not revoked" cache
      // entry behind (or skipped its invalidation); drop it explicitly.
      await this.verificationCache.invalidateSessionRevocation(sessionId);
    }
  }

  /** Marks an access token as revoked for the remainder of its lifetime. */
  async revokeAccessToken(sessionId: string, ttlSeconds: number): Promise<void> {
    if (ttlSeconds <= 0) {
      return;
    }
    // Blacklist first, then drop the cached answer, so a concurrent request
    // re-verifying against the source of truth can never observe the write
    // before the invalidation and re-cache a stale "not revoked".
    await this.redis.set(this.accessKey(sessionId), '1', 'EX', ttlSeconds);
    await this.verificationCache.invalidateSessionRevocation(sessionId);
  }

  /** Marks a refresh token as revoked for the remainder of its lifetime. */
  async revokeRefreshToken(sessionId: string, ttlSeconds: number): Promise<void> {
    if (ttlSeconds <= 0) {
      return;
    }
    await this.redis.set(this.refreshKey(sessionId), '1', 'EX', ttlSeconds);
    await this.verificationCache.invalidateSessionRevocation(sessionId);
  }

  /** True when the session's access token has been blacklisted. */
  async isAccessTokenRevoked(sessionId: string): Promise<boolean> {
    if (!sessionId) {
      return false;
    }
    const exists = await this.redis.exists(this.accessKey(sessionId));
    return exists > 0;
  }

  /** True when the session's refresh token has been blacklisted. */
  async isRefreshTokenRevoked(sessionId: string): Promise<boolean> {
    if (!sessionId) {
      return false;
    }
    const exists = await this.redis.exists(this.refreshKey(sessionId));
    return exists > 0;
  }

  private accessKey(sessionId: string): string {
    return `auth:blacklist:access:${sessionId}`;
  }

  private refreshKey(sessionId: string): string {
    return `auth:blacklist:refresh:${sessionId}`;
  }
}
