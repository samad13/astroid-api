import { Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { AuthConfig } from '../../config/auth.config';
import { TokenBlacklistService } from './services/token-blacklist.service';
import { TokenVerificationCacheService } from './services/token-verification-cache.service';
import {
  AuthenticatedUser,
  JwtAccessPayload,
} from '../../common/interfaces/authenticated-user.interface';

/**
 * Validates the access-token JWT on protected routes and resolves the
 * {@link AuthenticatedUser} principal attached to the request. Signature and
 * expiry are checked by passport-jwt; this strategy maps claims to the
 * principal and rejects tokens whose session has been revoked via the
 * Redis-backed blacklist (e.g. after logout). The check fails open if Redis is
 * unreachable so a cache outage does not lock everyone out.
 *
 * Revocation checks go through the {@link TokenVerificationCacheService}: the
 * blacklist answer is cached for a short TTL so authenticated requests avoid
 * one Redis round trip each, and every revocation path invalidates the cached
 * entry, so revocations are still observed immediately.
 */
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  private readonly logger = new Logger(JwtStrategy.name);

  constructor(
    config: ConfigService,
    private readonly tokenBlacklist: TokenBlacklistService,
    private readonly verificationCache: TokenVerificationCacheService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: config.getOrThrow<AuthConfig>('auth').accessSecret,
    });
  }

  async validate(payload: JwtAccessPayload): Promise<AuthenticatedUser> {
    if (!payload?.sub || !payload.organizationId) {
      throw new UnauthorizedException('Malformed access token');
    }

    if (payload.sessionId) {
      let revoked = false;
      try {
        // Cache-first: reads hit the short-TTL cache; misses fall through to
        // the Redis blacklist and store the answer for the next requests.
        const result = await this.verificationCache.resolveSessionRevocation(
          payload.sessionId,
          () => this.tokenBlacklist.isAccessTokenRevoked(payload.sessionId as string),
        );
        revoked = result.revoked;
      } catch (error: unknown) {
        // Fail open on Redis outages rather than rejecting every request.
        this.logger.warn(
          `Blacklist check failed, allowing request: ${(error as Error).message}`,
        );
      }
      if (revoked) {
        throw new UnauthorizedException('Session has been revoked');
      }
    }

    return {
      id: payload.sub,
      organizationId: payload.organizationId,
      email: payload.email,
      role: payload.role,
      sessionId: payload.sessionId,
    };
  }
}