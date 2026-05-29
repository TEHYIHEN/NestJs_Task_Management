import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { ConfigModule } from '@nestjs/config';
import jwtConfig from './config/jwt.config';
import { JwtModule } from '@nestjs/jwt';
import {refreshjwtConfig, verifyrefreshjwtConfig} from './config/refreshjwt.config';

@Module({
  imports: [
    // default jwt to whole auth 
    JwtModule.registerAsync(jwtConfig.asProvider()), 
    
    ConfigModule.forFeature(jwtConfig),  // register it for dependency injection(DI)
    ConfigModule.forFeature(refreshjwtConfig),
    ConfigModule.forFeature(verifyrefreshjwtConfig)
  ],
  controllers: [AuthController],
  providers: [AuthService]
})
export class AuthModule {}
