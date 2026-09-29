import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Controller, ExecutionContext, Get, Post, UseGuards } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { PassportModule } from '@nestjs/passport';
import { JwtAuthGuard } from '../../../common/guards/jwt-auth.guard';
import { ApiKeyAuthGuard } from '../../../common/guards/api-key-auth.guard';
import { ScopesGuard } from '../../../common/guards/scopes.guard';
import { RequireScopes } from '../../../common/decorators/scopes.decorator';
import { CurrentUser } from '../../../common/decorators/current-user.decorator';
import { AuthenticatedUser } from '../../../common/interfaces/authenticated-user.interface';
import { ApiKeyStrategy } from '../api-key.strategy';
import { ApiKeyService } from '../../developer/api-key.service';
import { sha256 } from '../../../utils/crypto.util';

import { ConfigService } from '@nestjs/config';
import { JwtStrategy } from '../jwt.strategy';
import { TokenBlacklistService } from '../services/token-blacklist.service';
import { TokenVerificationCacheService } from '../services/token-verification-cache.service';

@Controller('test-resource')
@UseGuards(JwtAuthGuard, ScopesGuard)
class TestProtectedController {
  @Get('public-unscoped')
  getUnscoped(@CurrentUser() user: AuthenticatedUser) {
    return { status: 'success', organizationId: user.organizationId };
  }

  @Post('transactions')
  @RequireScopes('transactions:write')
  createTransaction(@CurrentUser() user: AuthenticatedUser) {
    return { status: 'created', keyId: user.apiKeyId ?? user.id };
  }
}

describe('API Key Authentication with Scoped Permissions (Integration)', () => {
  let app: TestingModule;
  let apiKeyService: { verify: ReturnType<typeof vi.fn> };
  let jwtAuthGuard: JwtAuthGuard;
  let apiKeyAuthGuard: ApiKeyAuthGuard;
  let scopesGuard: ScopesGuard;

  const validKey = 'ak_live_validkey1234567890abcdef1234567890abcdef';
  const orgId = 'org-integration-1';

  beforeEach(async () => {
    apiKeyService = {
      verify: vi.fn(),
    };

    const mockConfig = {
      getOrThrow: vi.fn().mockReturnValue({ accessSecret: 'secret-must-be-at-least-16-bytes' }),
    };
    const mockBlacklist = {
      isAccessTokenRevoked: vi.fn().mockResolvedValue(false),
    };
    const mockVerificationCache = {
      resolveSessionRevocation: vi.fn().mockResolvedValue({ revoked: false, verifiedAt: Date.now() }),
    };

    app = await Test.createTestingModule({
      imports: [PassportModule.register({ defaultStrategy: 'jwt' })],
      controllers: [TestProtectedController],
      providers: [
        { provide: ConfigService, useValue: mockConfig },
        { provide: TokenVerificationCacheService, useValue: mockVerificationCache },
        { provide: TokenBlacklistService, useValue: mockBlacklist },
        JwtStrategy,
        ApiKeyStrategy,
        { provide: ApiKeyService, useValue: apiKeyService },
        JwtAuthGuard,
        ApiKeyAuthGuard,
        ScopesGuard,
      ],
    }).compile();

    jwtAuthGuard = app.get<JwtAuthGuard>(JwtAuthGuard);
    apiKeyAuthGuard = app.get<ApiKeyAuthGuard>(ApiKeyAuthGuard);
    scopesGuard = app.get<ScopesGuard>(ScopesGuard);
  });

  const createExecutionContext = (
    headers: Record<string, string>,
    // eslint-disable-next-line @typescript-eslint/no-unsafe-function-type
    handler: Function,
  ): ExecutionContext => {
    const req: Record<string, unknown> = {
      headers,
    };
    return {
      getHandler: () => handler,
      getClass: () => TestProtectedController,
      switchToHttp: () => ({
        getRequest: () => req,
        getResponse: () => ({}),
      }),
    } as unknown as ExecutionContext;
  };

  it('authenticates API key and allows access to unscoped protected route', async () => {
    apiKeyService.verify.mockImplementation((key) => {
      if (key === validKey) {
        return Promise.resolve({
          id: 'key-100',
          organizationId: orgId,
          name: 'Integration Test Key',
          prefix: 'ak_live_validk',
          hashedKey: sha256(validKey),
          permissions: ['transactions:read'],
          allowedIps: [],
        });
      }
      return Promise.resolve(null);
    });

    const handler = TestProtectedController.prototype.getUnscoped;
    const context = createExecutionContext({ 'x-api-key': validKey }, handler);

    const canAuth = await jwtAuthGuard.canActivate(context);
    expect(canAuth).toBe(true);

    const canScope = scopesGuard.canActivate(context);
    expect(canScope).toBe(true);

    const req = context.switchToHttp().getRequest();
    expect(req.user).toMatchObject({
      id: 'key-100',
      organizationId: orgId,
      isApiKey: true,
    });
  });

  it('allows access to scoped route when API key has exact scope', async () => {
    apiKeyService.verify.mockResolvedValue({
      id: 'key-101',
      organizationId: orgId,
      name: 'Write Key',
      prefix: 'ak_live_validk',
      hashedKey: sha256(validKey),
      permissions: ['transactions:write'],
      allowedIps: [],
    });

    const handler = TestProtectedController.prototype.createTransaction;
    const context = createExecutionContext({ 'x-api-key': validKey }, handler);

    const canAuth = await jwtAuthGuard.canActivate(context);
    expect(canAuth).toBe(true);

    const canScope = scopesGuard.canActivate(context);
    expect(canScope).toBe(true);
  });

  it('allows access to scoped route when API key has wildcard scope', async () => {
    apiKeyService.verify.mockResolvedValue({
      id: 'key-102',
      organizationId: orgId,
      name: 'Wildcard Key',
      prefix: 'ak_live_validk',
      hashedKey: sha256(validKey),
      permissions: ['transactions:*'],
      allowedIps: [],
    });

    const handler = TestProtectedController.prototype.createTransaction;
    const context = createExecutionContext({ 'x-api-key': validKey }, handler);

    await jwtAuthGuard.canActivate(context);
    const canScope = scopesGuard.canActivate(context);
    expect(canScope).toBe(true);
  });

  it('denies access with 403 Forbidden when API key is missing required scope', async () => {
    apiKeyService.verify.mockResolvedValue({
      id: 'key-103',
      organizationId: orgId,
      name: 'Read Only Key',
      prefix: 'ak_live_validk',
      hashedKey: sha256(validKey),
      permissions: ['transactions:read', 'policies:read'],
      allowedIps: [],
    });

    const handler = TestProtectedController.prototype.createTransaction;
    const context = createExecutionContext({ 'x-api-key': validKey }, handler);

    await jwtAuthGuard.canActivate(context);
    expect(() => scopesGuard.canActivate(context)).toThrowError(
      /Insufficient API key permissions.*transactions:write/,
    );
  });

  it('denies access with 401 Unauthorized when API key is invalid', async () => {
    apiKeyService.verify.mockResolvedValue(null);

    const handler = TestProtectedController.prototype.createTransaction;
    const context = createExecutionContext({ 'x-api-key': 'ak_live_invalidkey' }, handler);

    await expect(jwtAuthGuard.canActivate(context)).rejects.toThrow();
  });

  it('ApiKeyAuthGuard authenticates valid keys and ScopesGuard returns 403 for missing scopes', async () => {
    apiKeyService.verify.mockResolvedValue({
      id: 'key-200',
      organizationId: orgId,
      name: 'Read Only Key',
      prefix: 'ak_live_validk',
      hashedKey: sha256(validKey),
      permissions: ['transactions:read'],
      allowedIps: [],
    });

    const handler = TestProtectedController.prototype.createTransaction;
    const context = createExecutionContext({ 'x-api-key': validKey }, handler);

    await expect(apiKeyAuthGuard.canActivate(context)).resolves.toBe(true);
    expect(() => scopesGuard.canActivate(context)).toThrowError(
      /Insufficient API key permissions.*transactions:write/,
    );
  });
});
