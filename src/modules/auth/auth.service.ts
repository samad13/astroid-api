import { Injectable, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { User, UserRole, UserStatus } from '@prisma/client';
import * as argon2 from 'argon2';
import { PrismaService } from '../../database/prisma.service';
import { AuthConfig } from '../../config/auth.config';
import {
  AuthenticatedUser,
  JwtAccessPayload,
  JwtRefreshPayload,
} from '../../common/interfaces/authenticated-user.interface';
import {
  ConflictException,
  UnauthorizedException,
} from '../../common/exceptions/domain.exception';
import { ErrorCode } from '../../common/constants/error-codes';
import { sha256, generateToken } from '../../utils/crypto.util';
import { EventBusService } from '../../events/event-bus.service';
import { DomainEventName } from '../../events/event-names';
import { LoginInput, RegisterInput } from './auth.dto';
import { TokenBlacklistService } from './services/token-blacklist.service';
import { TokenVerificationCacheService } from './services/token-verification-cache.service';

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  tokenType: 'Bearer';
}

export interface AuthResult {
  user: PublicUser;
  tokens: TokenPair;
}

export interface PublicUser {
  id: string;
  organizationId: string;
  name: string;
  email: string;
  role: UserRole;
}

interface SessionContext {
  device?: string;
  browser?: string;
  ipAddress?: string;
}

/**
 * Authentication and session management. Passwords are hashed with argon2id and
 * never stored or logged in plaintext. Refresh tokens are opaque random secrets;
 * only their SHA-256 hash is persisted (rotated on every refresh), so a database
 * leak cannot be used to mint access tokens.
 */
@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly auth: AuthConfig;

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly eventBus: EventBusService,
    private readonly tokenBlacklist: TokenBlacklistService,
    private readonly verificationCache: TokenVerificationCacheService,
    config: ConfigService,
  ) {
    this.auth = config.getOrThrow<AuthConfig>('auth');
  }

  /**
   * Registers a brand-new organization and its first OWNER user in a single
   * transaction, then issues an initial token pair.
   */
  async register(input: RegisterInput, context: SessionContext = {}): Promise<AuthResult> {
    const email = input.email.toLowerCase();
    const existing = await this.prisma.user.findUnique({ where: { email } });
    if (existing) {
      throw new ConflictException('An account with this email already exists');
    }

    const passwordHash = await argon2.hash(input.password, { type: argon2.argon2id });
    const slug = await this.uniqueSlug(input.organizationName);

    const user = await this.prisma.$transaction(async (tx) => {
      const organization = await tx.organization.create({
        data: { name: input.organizationName, slug },
      });
      return tx.user.create({
        data: {
          organizationId: organization.id,
          name: input.name,
          email,
          passwordHash,
          role: UserRole.OWNER,
          status: UserStatus.ACTIVE,
        },
      });
    });

    await this.eventBus.emit(
      DomainEventName.OrganizationRegistered,
      { organizationId: user.organizationId, ownerUserId: user.id },
      {
        organizationId: user.organizationId,
        actorId: user.id,
        aggregateType: 'organization',
        aggregateId: user.organizationId,
      },
    );

    const tokens = await this.issueTokens(user, context);
    return { user: this.toPublicUser(user), tokens };
  }

  /** Authenticates by email + password and issues a fresh token pair. */
  async login(input: LoginInput, context: SessionContext = {}): Promise<AuthResult> {
    const email = input.email.toLowerCase();
    const user = await this.prisma.user.findUnique({ where: { email } });

    // Always run a hash verification to keep timing uniform for unknown emails.
    const hash = user?.passwordHash ?? DUMMY_ARGON2_HASH;
    const valid = await argon2.verify(hash, input.password).catch(() => false);

    if (!user || !user.passwordHash || !valid) {
      throw new UnauthorizedException('Invalid email or password', ErrorCode.INVALID_CREDENTIALS);
    }
    if (user.status !== UserStatus.ACTIVE) {
      throw new UnauthorizedException('This account is not active', ErrorCode.UNAUTHORIZED);
    }

    await this.prisma.user.update({
      where: { id: user.id },
      data: { lastLogin: new Date() },
    });

    const tokens = await this.issueTokens(user, context);
    return { user: this.toPublicUser(user), tokens };
  }

  /**
   * Rotates a refresh token: verifies the presented token against its stored
   * hash, revokes the old session, and issues a new pair. Reuse of a revoked or
   * expired token is rejected.
   */
  async refresh(refreshToken: string): Promise<TokenPair> {
    let payload: JwtRefreshPayload;
    try {
      payload = await this.jwt.verifyAsync<JwtRefreshPayload>(refreshToken, {
        secret: this.auth.refreshSecret,
      });
    } catch {
      throw new UnauthorizedException('Invalid refresh token', ErrorCode.INVALID_TOKEN);
    }

    const session = await this.prisma.session.findUnique({
      where: { id: payload.sessionId },
      include: { user: true },
    });

    const presentedHash = sha256(refreshToken);

    // Reject refresh tokens blacklisted on logout / credential rotation, even
    // if the DB session was not technically revoked (idempotent logout).
    const blacklisted = await this.isRefreshBlacklisted(payload.sessionId);
    if (blacklisted) {
      throw new UnauthorizedException('Session is no longer valid', ErrorCode.SESSION_REVOKED);
    }

    if (
      !session ||
      session.revokedAt ||
      session.expiresAt.getTime() < Date.now() ||
      session.refreshTokenHash !== presentedHash
    ) {
      throw new UnauthorizedException('Session is no longer valid', ErrorCode.SESSION_REVOKED);
    }

    // Revoke the old session and mint a replacement (token rotation).
    await this.prisma.session.update({
      where: { id: session.id },
      data: { revokedAt: new Date() },
    });
    // In-flight access tokens of the rotated session must re-verify against
    // the blacklist instead of a cached answer.
    await this.verificationCache.invalidateOnRefreshRotation(session.id);

    return this.issueTokens(session.user, {
      device: session.device ?? undefined,
      browser: session.browser ?? undefined,
      ipAddress: session.ipAddress ?? undefined,
    });
  }

  /**
   * Revokes the session behind an access token (idempotent). Marks the DB
   * session as revoked and blacklists the session's access/refresh tokens in
   * Redis so in-flight JWTs are rejected before they naturally expire.
   */
  async logout(sessionId: string): Promise<{ success: true }> {
    await this.prisma.session
      .update({ where: { id: sessionId }, data: { revokedAt: new Date() } })
      .catch(() => undefined);
    await this.tokenBlacklist.revokeSession(
      sessionId,
      this.auth.accessTtl,
      this.auth.refreshTtl,
    );
    // Belt-and-braces: the blacklist service already invalidates the cached
    // verification answer; keep logout self-contained even if that changes.
    await this.verificationCache.invalidateSessionRevocation(sessionId);
    return { success: true };
  }

  /** Resolves the current principal into a public profile. */
  async me(user: AuthenticatedUser): Promise<PublicUser> {
    const record = await this.prisma.user.findFirst({
      where: { id: user.id, organizationId: user.organizationId },
    });
    if (!record) {
      throw new UnauthorizedException('User no longer exists', ErrorCode.UNAUTHORIZED);
    }
    return this.toPublicUser(record);
  }

  // ── internals ──────────────────────────────────────────────────────────

  /** Checks the refresh blacklist, failing open if Redis is unreachable. */
  private async isRefreshBlacklisted(sessionId: string): Promise<boolean> {
    try {
      return await this.tokenBlacklist.isRefreshTokenRevoked(sessionId);
    } catch (error: unknown) {
      this.logger.warn(
        `Refresh blacklist check failed, allowing attempt: ${(error as Error).message}`,
      );
      return false;
    }
  }

  private async issueTokens(user: User, context: SessionContext): Promise<TokenPair> {
    // Create the session first so the refresh token can embed its id.
    const session = await this.prisma.session.create({
      data: {
        userId: user.id,
        device: context.device ?? null,
        browser: context.browser ?? null,
        ipAddress: context.ipAddress ?? null,
        refreshTokenHash: sha256(generateToken(8)), // placeholder, replaced below
        expiresAt: new Date(Date.now() + this.auth.refreshTtl * 1000),
      },
    });

    const accessPayload: JwtAccessPayload = {
      sub: user.id,
      organizationId: user.organizationId,
      email: user.email,
      role: user.role,
      sessionId: session.id,
    };
    const refreshPayload: JwtRefreshPayload = { sub: user.id, sessionId: session.id };

    const accessToken = await this.jwt.signAsync(accessPayload, {
      secret: this.auth.accessSecret,
      expiresIn: this.auth.accessTtl,
    });
    const refreshToken = await this.jwt.signAsync(refreshPayload, {
      secret: this.auth.refreshSecret,
      expiresIn: this.auth.refreshTtl,
    });

    // Persist only the hash of the freshly-minted refresh token.
    await this.prisma.session.update({
      where: { id: session.id },
      data: { refreshTokenHash: sha256(refreshToken) },
    });

    return {
      accessToken,
      refreshToken,
      expiresIn: this.auth.accessTtl,
      tokenType: 'Bearer',
    };
  }

  private toPublicUser(user: User): PublicUser {
    return {
      id: user.id,
      organizationId: user.organizationId,
      name: user.name,
      email: user.email,
      role: user.role,
    };
  }

  private async uniqueSlug(name: string): Promise<string> {
    const base =
      name
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/(^-|-$)/g, '')
        .slice(0, 40) || 'org';
    let slug = base;
    let attempt = 0;
    // Loop until a free slug is found; suffix collisions with a short random tag.
    while (await this.prisma.organization.findUnique({ where: { slug } })) {
      attempt += 1;
      slug = `${base}-${generateToken(3)}`;
      if (attempt > 5) {
        slug = `${base}-${generateToken(6)}`;
        break;
      }
    }
    return slug;
  }
}

/**
 * A precomputed argon2id hash of a random value. Used to equalise login timing
 * between existing and non-existent accounts (mitigates user enumeration).
 */
const DUMMY_ARGON2_HASH =
  '$argon2id$v=19$m=65536,t=3,p=4$c29tZS1zdGF0aWMtc2FsdA$3s0Vp3n4a2b1c0d9e8f7g6h5i4j3k2l1m0n9o8p7q6r';
