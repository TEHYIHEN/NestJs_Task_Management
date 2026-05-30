import { Controller, Post, Body, UseGuards, Res, Req } from '@nestjs/common';
import { type Response, Request } from 'express';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { JwtRefreshGuard } from './guards/jwt-refresh.guard';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { LocalAuthGuard } from './guards/local-auth.guard';
import { CurrentUser } from './decorators/current-user.decorator';
import { Public } from './decorators/public.decorator';

const COOKIE_OPTIONS = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax' as const,
  maxAge: 7 * 24 * 60 * 60 * 1000,
};

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Public()
  @Post('register')
  async register(
    @Body() dto: RegisterDto,
    @Res({ passthrough: true }) res: Response,
  ) {
    const { refreshToken, ...result } = await this.authService.register(dto);
    res.cookie('refresh_token', refreshToken, COOKIE_OPTIONS);
    return result;
  }

  @UseGuards(LocalAuthGuard) // 触发 LocalStrategy → validateUser()
  @Post('login')
  async login(
    @CurrentUser() user: { id: string },
    @Res({ passthrough: true }) res: Response,
  ) {
    const { refreshToken, ...result } = await this.authService.login(user.id);
    res.cookie('refresh_token', refreshToken, COOKIE_OPTIONS);
    return result;
  }

  @UseGuards(JwtRefreshGuard) // 触发 JwtRefreshStrategy → validateRefreshToken()
  @Post('refresh')
  async refresh(
    @CurrentUser() user: { id: string; jti: string },
    @Res({ passthrough: true }) res: Response,
  ) {
    const { refreshToken, accessToken } = await this.authService.refreshTokens(
      user.id,
      user.jti,
    );
    res.cookie('refresh_token', refreshToken, COOKIE_OPTIONS);
    return { accessToken };
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  async logout(
    @CurrentUser() user: { id: string; jti: string },
    @Res({ passthrough: true }) res: Response,
  ) {
    res.clearCookie('refresh_token', COOKIE_OPTIONS);
    return this.authService.logout(user.jti);
  }
}