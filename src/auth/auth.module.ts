import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { ConfigModule } from '@nestjs/config';
import jwtConfig from './config/jwt.config';
import { JwtModule } from '@nestjs/jwt';
import {refreshjwtConfig, verifyrefreshjwtConfig} from './config/refreshjwt.config';
import { UsersService } from 'src/users/users.service';
import { LocalStrategy } from './strategies/local.strategy';
import { JwtStrategy } from './strategies/jwt.strategy';
import { RefreshJwtStrategy } from './strategies/refresh.strategy';
import { JwtAuthGuard } from './guards/jwt-auth.guard';

@Module({
  imports: [
    // default jwt to whole auth 
    JwtModule.registerAsync(jwtConfig.asProvider()), 
    
    ConfigModule.forFeature(jwtConfig),  // register it for dependency injection(DI)
    ConfigModule.forFeature(refreshjwtConfig),
    ConfigModule.forFeature(verifyrefreshjwtConfig)
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    UsersService,
    LocalStrategy,
    JwtStrategy,
    RefreshJwtStrategy,
    {
      provide:"APP_GUARD",
      useClass: JwtAuthGuard
    },
  ]
})
export class AuthModule {}
