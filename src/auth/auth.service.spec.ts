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
import { refreshjwtConfig, verifyrefreshjwtConfig } from './config/refreshjwt.config';

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

  const mockRefreshToken = {
    id: 'mock-jti-uuid',
    userId: 'user-id-123',
    token: 'hashed-refresh-token',
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
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
            get: jest.fn(),
          },
        },
        {
          provide: PrismaService,
          useValue: prismaMock,
        },
        // mock @Inject(refreshjwtConfig.KEY)
        {
          provide: refreshjwtConfig.KEY,
          useValue: {
            secret: 'test-refresh-secret',
            expiresIn: '7d',
          },
        },
        // mock @Inject(verifyrefreshjwtConfig.KEY)
        {
          provide: verifyrefreshjwtConfig.KEY,
          useValue: {
            secret: 'test-refresh-secret',
          },
        },
      ],
    }).compile();

    authService = module.get<AuthService>(AuthService);
    usersService = module.get(UsersService);
    jwtService = module.get(JwtService);
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

      const result = await authService.validateUser(
        'test@example.com',
        '123456',
      );

      expect(result).toEqual({ id: mockUser.id });
      expect(usersService.findByEmail).toHaveBeenCalledWith('test@example.com');
      expect(argon2.verify).toHaveBeenCalledWith(mockUser.password, '123456');
    });

    it('should throw UnauthorizedException if user not found', async () => {
      usersService.findByEmail.mockResolvedValue(null);

      await expect(
        authService.validateUser('wrong@example.com', '123456'),
      ).rejects.toThrow(UnauthorizedException);

      expect(argon2.verify).not.toHaveBeenCalled();
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
    it('should return CurrentUser if user exists', async () => {
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
    it('should return id and jti if refresh token is valid', async () => {
      jwtService.verifyAsync.mockResolvedValue({
        sub: mockUser.id,
        jti: 'mock-jti-uuid',
      });
      prismaMock.refreshToken.findUnique.mockResolvedValue(mockRefreshToken);
      (argon2.verify as jest.Mock).mockResolvedValue(true);

      const result = await authService.validateRefreshToken(
        mockUser.id,
        'mock-refresh-token',
      );

      expect(result).toEqual({ id: mockUser.id, jti: 'mock-jti-uuid' });
      expect(prismaMock.refreshToken.findUnique).toHaveBeenCalledWith({
        where: { id: 'mock-jti-uuid' },
      });
    });

    it('should throw UnauthorizedException if JWT verify fails', async () => {
      jwtService.verifyAsync.mockRejectedValue(new Error('invalid token'));

      await expect(
        authService.validateRefreshToken(mockUser.id, 'invalid-token'),
      ).rejects.toThrow();
    });

    it('should throw UnauthorizedException if token not found in database', async () => {
      jwtService.verifyAsync.mockResolvedValue({
        sub: mockUser.id,
        jti: 'mock-jti-uuid',
      });
      prismaMock.refreshToken.findUnique.mockResolvedValue(null);

      await expect(
        authService.validateRefreshToken(mockUser.id, 'mock-refresh-token'),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException if token is expired', async () => {
      jwtService.verifyAsync.mockResolvedValue({
        sub: mockUser.id,
        jti: 'mock-jti-uuid',
      });
      prismaMock.refreshToken.findUnique.mockResolvedValue({
        ...mockRefreshToken,
        expiresAt: new Date(Date.now() - 1000), // 过期
      });

      await expect(
        authService.validateRefreshToken(mockUser.id, 'mock-refresh-token'),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException if argon2 verify fails', async () => {
      jwtService.verifyAsync.mockResolvedValue({
        sub: mockUser.id,
        jti: 'mock-jti-uuid',
      });
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
      (argon2.hash as jest.Mock).mockResolvedValue('hashed-password');
      usersService.create.mockResolvedValue(mockUser);
      jwtService.signAsync
        .mockResolvedValueOnce('mock-access-token')
        .mockResolvedValueOnce('mock-refresh-token');
      prismaMock.refreshToken.create.mockResolvedValue(mockRefreshToken);

      const result = await authService.register(registerDto);

      expect(result).toHaveProperty('accessToken', 'mock-access-token');
      expect(result).toHaveProperty('refreshToken', 'mock-refresh-token');
      expect(result.user).not.toHaveProperty('password');
      expect(usersService.create).toHaveBeenCalledTimes(1);
      expect(argon2.hash).toHaveBeenCalledWith(registerDto.password);
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
    it('should return tokens and sanitized user on success', async () => {
      usersService.findById.mockResolvedValue(mockUser);
      jwtService.signAsync
        .mockResolvedValueOnce('mock-access-token')
        .mockResolvedValueOnce('mock-refresh-token');
      prismaMock.refreshToken.create.mockResolvedValue(mockRefreshToken);

      const result = await authService.login(mockUser.id);

      expect(result).toHaveProperty('accessToken', 'mock-access-token');
      expect(result).toHaveProperty('refreshToken', 'mock-refresh-token');
      expect(result.user).not.toHaveProperty('password');
    });

    it('should throw UnauthorizedException if user not found', async () => {
      usersService.findById.mockResolvedValue(null);

      await expect(authService.login('non-existent-id')).rejects.toThrow(
        UnauthorizedException,
      );

      expect(jwtService.signAsync).not.toHaveBeenCalled();
    });
  });

  // ─── logout ───────────────────────────────────────────────

  describe('logout', () => {
    it('should delete refresh token and return success message', async () => {
      prismaMock.refreshToken.deleteMany.mockResolvedValue({ count: 1 });

      const result = await authService.logout('mock-jti-uuid');

      expect(result).toEqual({ message: 'Logged out successfully' });
      expect(prismaMock.refreshToken.deleteMany).toHaveBeenCalledWith({
        where: { id: 'mock-jti-uuid' },
      });
    });

    it('should still succeed if token already deleted', async () => {
      prismaMock.refreshToken.deleteMany.mockResolvedValue({ count: 0 });

      const result = await authService.logout('non-existent-jti');

      expect(result).toEqual({ message: 'Logged out successfully' });
    });
  });

  // ─── refreshTokens ────────────────────────────────────────

  describe('refreshTokens', () => {
    it('should return new tokens on valid refresh', async () => {
      usersService.findById.mockResolvedValue(mockUser);
      prismaMock.refreshToken.delete.mockResolvedValue(mockRefreshToken);
      jwtService.signAsync
        .mockResolvedValueOnce('new-access-token')
        .mockResolvedValueOnce('new-refresh-token');
      prismaMock.refreshToken.create.mockResolvedValue(mockRefreshToken);

      const result = await authService.refreshTokens(
        mockUser.id,
        'mock-jti-uuid',
      );

      expect(result).toHaveProperty('accessToken', 'new-access-token');
      expect(result).toHaveProperty('refreshToken', 'new-refresh-token');
      expect(prismaMock.refreshToken.delete).toHaveBeenCalledWith({
        where: { id: 'mock-jti-uuid' },
      });
    });

    it('should throw UnauthorizedException if user not found', async () => {
      usersService.findById.mockResolvedValue(null);

      await expect(
        authService.refreshTokens('non-existent-id', 'mock-jti-uuid'),
      ).rejects.toThrow(UnauthorizedException);

      expect(prismaMock.refreshToken.delete).not.toHaveBeenCalled();
    });
  });
});