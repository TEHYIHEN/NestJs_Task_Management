import { Inject, Injectable, UnauthorizedException } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import {refreshjwtConfig} from "../config/refreshjwt.config";
import { AuthService } from "../auth.service";
import { ExtractJwt, Strategy } from "passport-jwt";
import type { ConfigType } from "@nestjs/config";
import { AuthJwtPayload } from "../types/auth.jwtPayload";
import { Request } from "express";



@Injectable()
export class RefreshJwtStrategy extends PassportStrategy(Strategy, "refresh-jwt"){

    constructor(
        @Inject(refreshjwtConfig.KEY)
        refreshJwtConfiguration: ConfigType<typeof refreshjwtConfig>,
        private authService: AuthService
    ){
        super({
            jwtFromRequest: ExtractJwt.fromExtractors([(req: Request) => req?.cookies?.refresh_token ?? null]),
            ignoreExpiration: false,
            secretOrKey: refreshJwtConfiguration.secret as string,
            passReqToCallback: true,
        })

    }

    async validate(req: Request, payload: AuthJwtPayload){

        const refreshToken = req?.cookies?.refresh_token;
        const userId = payload.sub;

        if(!refreshToken){
            throw new UnauthorizedException();
        }

        return this.authService.validateRefreshToken(userId, refreshToken)
    }
}