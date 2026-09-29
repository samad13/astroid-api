import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtStrategy } from './jwt.strategy';
import { ApiKeyStrategy } from './api-key.strategy';
import { ApiKeyGuard } from '../../common/guards/api-key.guard';
import { ApiKeyAuthGuard } from '../../common/guards/api-key-auth.guard';
import { ScopesGuard } from '../../common/guards/scopes.guard';
import { TokenBlacklistService } from './services/token-blacklist.service';
import { TokenVerificationCacheService } from './services/token-verification-cache.service';
import { CacheService } from '../../common/cache/cache.service';
import { PasskeyController } from './controllers/passkey.controller';
import { PasskeyService } from './services/passkey.service';
import { REDIS_CLIENT } from '../../common/locks/locks.constants';

/**
 * Authentication module. Registers passport-jwt and api-key strategies and a bare
 * JwtModule (per-call secrets are supplied explicitly by AuthService so the
 * access and refresh tokens can use different signing keys). Also provides the
 * Redis client used by the token blacklist, which lets logout / credential
 * rotation invalidate in-flight JWTs before they naturally expire.
 *
 * Revocation answers are cached by {@link TokenVerificationCacheService} over
 * the shared {@link REDIS_CLIENT} (via {@link CacheService}) so authenticated
 * requests avoid one Redis round trip each; every revocation path invalidates
 * the cached entry.
 */
@Module({
  imports: [PassportModule.register({ defaultStrategy: 'jwt' }), JwtModule.register({})],
  controllers: [AuthController, PasskeyController],
  providers: [
    CacheService,
    TokenVerificationCacheService,
    AuthService,
    JwtStrategy,
    ApiKeyStrategy,
    ApiKeyGuard,
    ApiKeyAuthGuard,
    ScopesGuard,
    PasskeyService,
    TokenBlacklistService,
  ],
  exports: [
    AuthService,
    JwtStrategy,
    ApiKeyStrategy,
    ApiKeyGuard,
    ApiKeyAuthGuard,
    ScopesGuard,
    PasskeyService,
    TokenBlacklistService,
    TokenVerificationCacheService,
  ],
})
export class AuthModule {}
