import { registerAs } from '@nestjs/config';
import { JwtModuleOptions, JwtSignOptions, JwtVerifyOptions } from '@nestjs/jwt';
import { StringValue } from 'ms';

export const refreshjwtConfig = registerAs('refreshjwt', (): JwtSignOptions=> ({
  secret: process.env.JWT_REFRESH_SECRET,
  expiresIn: process.env.JWT_REFRESH_EXPIRES_IN as StringValue
  
}));

export const verifyrefreshjwtConfig = registerAs('verifyrefreshjwt',(): JwtVerifyOptions =>({
  secret: process.env.JWT_REFRESH_SECRET,
}))