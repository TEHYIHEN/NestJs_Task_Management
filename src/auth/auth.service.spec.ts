import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { UsersService } from '../users/users.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import { createPrismaMock, PrismaMock } from '../prisma/prisma.mock';
import { ConflictException, UnauthorizedException } from '@nestjs/common';
import { Role } from '@prisma/client';
import * as argon2 from 'argon2';

// mock argon2
jest.mock('argon2', () => ({
  hash: jest.fn(),
  verify: jest.fn(),
}));

// mock randomUUID
jest.mock('crypto', () => ({
  randomUUID: jest.fn(() => 'mock-jti-uuid'),
}));

describe('AuthService', () => {
  let authService: AuthService;
  let usersService: jest.Mocked<UsersService>;
  let jwtService: jest.Mocked<JwtService>;
  let configService: jest.Mocked<ConfigService>;
  let prismaMock: PrismaMock;

  // ─── Mock Data ───────────────────────────────────────────

  const mockUser = {
    id: 'user-id-123',
    email: 'test@example.com',
    password: 'hashed-password',
    name: 'Test User',
    role: Role.MEMBER,
    createdAt: new Date(),
  };

  const mockTokens = {
    accessToken: 'mock-access-token',
    refreshToken: 'mock-refresh-token',
    jti: 'mock-jti-uuid',
  };

  const mockRefreshToken = {
    id: 'mock-jti-uuid',
    userId: 'user-id-123',
    token: 'hashed-refresh-token',
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days from now
    createdAt: new Date(),
  };

  // ─── Setup ───────────────────────────────────────────────

  beforeEach(async () => {
    prismaMock = createPrismaMock();

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: UsersService,
          useValue: {
            findByEmail: jest.fn(),
            findById: jest.fn(),
            create: jest.fn(),
          },
        },
        {
          provide: JwtService,
          useValue: {
            signAsync: jest.fn(),
            verifyAsync: jest.fn(),
          },
        },
        {
          provide: ConfigService,
          useValue: {
            get: jest.fn((key: string) => {
              const config: Record<string, string> = {
                JWT_SECRET: 'test-jwt-secret',
                JWT_EXPIRES_IN: '15m',
                JWT_REFRESH_SECRET: 'test-refresh-secret',
                JWT_REFRESH_EXPIRES_IN: '7d',
              };
              return config[key];
            }),
          },
        },
        {
          provide: PrismaService,
          useValue: prismaMock,
        },
      ],
    }).compile();

    authService = module.get<AuthService>(AuthService);
    usersService = module.get(UsersService);
    jwtService = module.get(JwtService);
    configService = module.get(ConfigService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  // ─── sanitizeUser ─────────────────────────────────────────

  describe('sanitizeUser', () => {
    it('should remove password from user object', () => {
      const result = authService.sanitizeUser(mockUser);
      expect(result).not.toHaveProperty('password');
      expect(result).toHaveProperty('id');
      expect(result).toHaveProperty('email');
      expect(result).toHaveProperty('role');
    });
  });

  // ─── validateUser ─────────────────────────────────────────

  describe('validateUser', () => {
    it('should return user id if credentials are valid', async () => {
      usersService.findByEmail.mockResolvedValue(mockUser);
      (argon2.verify as jest.Mock).mockResolvedValue(true);

      const result = await authService.validateUser('test@example.com', '123456');

      expect(result).toEqual({ id: mockUser.id });
      expect(usersService.findByEmail).toHaveBeenCalledWith('test@example.com');
    });

    it('should throw UnauthorizedException if user not found', async () => {
      usersService.findByEmail.mockResolvedValue(null);

      await expect(
        authService.validateUser('wrong@example.com', '123456'),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException if password is wrong', async () => {
      usersService.findByEmail.mockResolvedValue(mockUser);
      (argon2.verify as jest.Mock).mockResolvedValue(false);

      await expect(
        authService.validateUser('test@example.com', 'wrongpassword'),
      ).rejects.toThrow(UnauthorizedException);
    });
  });

  // ─── validateJwtUser ──────────────────────────────────────

  describe('validateJwtUser', () => {
    it('should return current user if user exists', async () => {
      usersService.findById.mockResolvedValue(mockUser);

      const result = await authService.validateJwtUser('user-id-123');

      expect(result).toEqual({
        id: mockUser.id,
        email: mockUser.email,
        role: mockUser.role,
      });
    });

    it('should throw UnauthorizedException if user not found', async () => {
      usersService.findById.mockResolvedValue(null);

      await expect(
        authService.validateJwtUser('non-existent-id'),
      ).rejects.toThrow(UnauthorizedException);
    });
  });

  // ─── validateRefreshToken ─────────────────────────────────

  describe('validateRefreshToken', () => {
    it('should return user id and jti if refresh token is valid', async () => {
      jwtService.verifyAsync.mockResolvedValue({ sub: mockUser.id, jti: 'mock-jti-uuid' });
      prismaMock.refreshToken.findUnique.mockResolvedValue(mockRefreshToken);
      (argon2.verify as jest.Mock).mockResolvedValue(true);

      const result = await authService.validateRefreshToken(mockUser.id, 'mock-refresh-token');

      expect(result).toEqual({ id: mockUser.id, jti: 'mock-jti-uuid' });
    });

    it('should throw UnauthorizedException if token is invalid JWT', async () => {
      jwtService.verifyAsync.mockRejectedValue(new Error('invalid token'));

      await expect(
        authService.validateRefreshToken(mockUser.id, 'invalid-token'),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException if token not found in database', async () => {
      jwtService.verifyAsync.mockResolvedValue({ sub: mockUser.id, jti: 'mock-jti-uuid' });
      prismaMock.refreshToken.findUnique.mockResolvedValue(null);

      await expect(
        authService.validateRefreshToken(mockUser.id, 'mock-refresh-token'),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException if token is expired', async () => {
      jwtService.verifyAsync.mockResolvedValue({ sub: mockUser.id, jti: 'mock-jti-uuid' });
      prismaMock.refreshToken.findUnique.mockResolvedValue({
        ...mockRefreshToken,
        expiresAt: new Date(Date.now() - 1000), // 过期了
      });

      await expect(
        authService.validateRefreshToken(mockUser.id, 'mock-refresh-token'),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException if argon2 verify fails', async () => {
      jwtService.verifyAsync.mockResolvedValue({ sub: mockUser.id, jti: 'mock-jti-uuid' });
      prismaMock.refreshToken.findUnique.mockResolvedValue(mockRefreshToken);
      (argon2.verify as jest.Mock).mockResolvedValue(false);

      await expect(
        authService.validateRefreshToken(mockUser.id, 'mock-refresh-token'),
      ).rejects.toThrow(UnauthorizedException);
    });
  });

  // ─── register ─────────────────────────────────────────────

  describe('register', () => {
    const registerDto = {
      email: 'new@example.com',
      password: '123456',
      name: 'New User',
    };

    it('should register a new user and return tokens', async () => {
      usersService.findByEmail.mockResolvedValue(null);
      usersService.create.mockResolvedValue(mockUser);
      (argon2.hash as jest.Mock).mockResolvedValue('hashed-password');
      jwtService.signAsync
        .mockResolvedValueOnce(mockTokens.accessToken)
        .mockResolvedValueOnce(mockTokens.refreshToken);
      prismaMock.refreshToken.create.mockResolvedValue(mockRefreshToken);

      const result = await authService.register(registerDto);

      expect(result).toHaveProperty('accessToken');
      expect(result).toHaveProperty('user');
      expect(result.user).not.toHaveProperty('password');
      expect(usersService.create).toHaveBeenCalledTimes(1);
    });

    it('should throw ConflictException if email already exists', async () => {
      usersService.findByEmail.mockResolvedValue(mockUser);

      await expect(authService.register(registerDto)).rejects.toThrow(
        ConflictException,
      );
      expect(usersService.create).not.toHaveBeenCalled();
    });
  });

  // ─── login ────────────────────────────────────────────────

  describe('login', () => {
    it('should return tokens and user on successful login', async () => {
      usersService.findById.mockResolvedValue(mockUser);
      jwtService.signAsync
        .mockResolvedValueOnce(mockTokens.accessToken)
        .mockResolvedValueOnce(mockTokens.refreshToken);
      prismaMock.refreshToken.create.mockResolvedValue(mockRefreshToken);

      const result = await authService.login(mockUser.id);

      expect(result).toHaveProperty('accessToken');
      expect(result).toHaveProperty('user');
      expect(result.user).not.toHaveProperty('password');
    });

    it('should throw UnauthorizedException if user not found', async () => {
      usersService.findById.mockResolvedValue(null);

      await expect(authService.login('non-existent-id')).rejects.toThrow(
        UnauthorizedException,
      );
    });
  });

  // ─── logout ───────────────────────────────────────────────

  describe('logout', () => {
    it('should delete refresh token and return success message', async () => {
      prismaMock.refreshToken.delete.mockResolvedValue(mockRefreshToken);

      const result = await authService.logout('mock-jti-uuid');

      expect(result).toEqual({ message: 'Logged out successfully' });
      expect(prismaMock.refreshToken.delete).toHaveBeenCalledWith({
        where: { id: 'mock-jti-uuid' },
      });
    });
  });

  // ─── refreshTokens ────────────────────────────────────────

  describe('refreshTokens', () => {
    it('should return new tokens on valid refresh', async () => {
      usersService.findById.mockResolvedValue(mockUser);
      prismaMock.refreshToken.delete.mockResolvedValue(mockRefreshToken);
      jwtService.signAsync
        .mockResolvedValueOnce(mockTokens.accessToken)
        .mockResolvedValueOnce(mockTokens.refreshToken);
      prismaMock.refreshToken.create.mockResolvedValue(mockRefreshToken);

      const result = await authService.refreshTokens(mockUser.id, 'mock-jti-uuid');

      expect(result).toHaveProperty('accessToken');
      expect(result).toHaveProperty('refreshToken');
      expect(prismaMock.refreshToken.delete).toHaveBeenCalledWith({
        where: { id: 'mock-jti-uuid' },
      });
    });

    it('should throw UnauthorizedException if user not found', async () => {
      usersService.findById.mockResolvedValue(null);

      await expect(
        authService.refreshTokens('non-existent-id', 'mock-jti-uuid'),
      ).rejects.toThrow(UnauthorizedException);
    });
  });
});