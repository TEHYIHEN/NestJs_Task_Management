import { ConflictException, Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService, type ConfigType } from '@nestjs/config';
import { PrismaService } from 'src/prisma/prisma.service';
import { UsersService } from 'src/users/users.service';
import { JwtService } from '@nestjs/jwt';
import { RegisterDto } from './dto/register.dto';
import * as argon2 from 'argon2';
import {refreshjwtConfig, verifyrefreshjwtConfig} from './config/refreshjwt.config';
import { CurrentUser } from './types/current-user';
import { randomUUID } from 'crypto';
import { User } from '@prisma/client';

@Injectable()
export class AuthService {

    constructor(
        private usersService: UsersService,
        private jwtService: JwtService,
        private configService: ConfigService,
        private prisma: PrismaService,

        @Inject(refreshjwtConfig.KEY)
        private refreshTokenConfig: ConfigType<typeof refreshjwtConfig>,

        @Inject(verifyrefreshjwtConfig.KEY)
        private verifyRefreshTokenConfig: ConfigType<typeof verifyrefreshjwtConfig>,

        /*
        JwtModule.registerAsync(jwtConfig)
        → jwtService.signAsync(payload) 
        → 自动用 jwtConfig 的 secret（access token）

        @Inject(refreshJwtConfig.KEY)
        → jwtService.signAsync(payload, this.refreshTokenConfig)
        → 手动传入 refresh secret
        
        为什么会分自动和手动》
        JwtModule.registerAsync(jwtConfig.asProvider())
        // 这个 secret 就是默认全局的，只能有一个，出现两个会被覆盖

        or
        auth.module
        JwtModule.register({})
        两个手动

        */
    ){}

    async register(dto: RegisterDto){

        //check email exist?
        const existing = await this.usersService.findByEmail(dto.email);
        if(existing){
            throw new ConflictException("Email already in use");
        }

        //hash password
        const hashed = await argon2.hash(dto.password);

        //create user
        const user = await this.usersService.create({
            email: dto.email,
            password: hashed,
            name: dto.name
        });

        const tokens = await this.generateTokens(user.id, user.email, user.role);
        await this.saveRefreshToken(user.id, tokens.refreshToken, tokens.jti)

        return {
            user: this.sanitizeUser(user),
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken
        }


    }

    async login(userId: string) {

        const user = await this.usersService.findById(userId);
        if (!user) throw new UnauthorizedException('Invalid credentials');

        const tokens = await this.generateTokens(user.id, user.email, user.role);
        await this.saveRefreshToken(user.id, tokens.refreshToken, tokens.jti);

        return { user: this.sanitizeUser(user), accessToken: tokens.accessToken, refreshToken: tokens.refreshToken };
    }

    async logout(jti:string){
        // delete: used for deleting a single unique record
        // If record does not exist, it will throw an error
        //await this.prisma.refreshToken.delete({where:{id:jti}});

        // deleteMany: used for deleting multiple records or safe deletion
        // If no matching record is found, it will not throw error and return { count: 0 } 
        // In logout case, token might already be expired or removed,
        // so using deleteMany is safer and makes the operation idempotent 
        await this.prisma.refreshToken.deleteMany({where:{id:jti}});

        return {message:"Logged out successfully"}
    }


    //--- Token Section ----
    
    async refreshTokens(userId: string, oldJti: string) {
        
        const user = await this.usersService.findById(userId);
        if(!user) throw new UnauthorizedException("Invalid refreshTokens");

        // 删除旧 token（rotation）
        await this.prisma.refreshToken.delete({where:{id:oldJti}})

        const tokens = await this.generateTokens(user.id, user.email, user.role);
        await this.saveRefreshToken(user.id, tokens.refreshToken, tokens.jti);

        return {accessToken: tokens.accessToken, refreshToken: tokens.refreshToken}


  }

    private async generateTokens(userId: string, email: string, role: string){

        const jti = randomUUID();
        const payload = {sub: userId, email, role, jti}

        const [accessToken, refreshToken] = await Promise.all([

            this.jwtService.signAsync(payload), //📌JwtModule.registerAsync(jwtConfig.asProvider()), 全局默认，所以没放this.jwtTokenConfig
            this.jwtService.signAsync(payload, this.refreshTokenConfig)
        ]);

        return {accessToken, refreshToken,jti};
    } 

    private async saveRefreshToken(userId: string, token: string, jti: string){

        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 7);

        const hashedToken = await argon2.hash(token);

        await this.prisma.refreshToken.create({
            data: {id: jti, userId, token: hashedToken, expiresAt}
        })
    }

    //--- Validate Methods with strategy ---

    async validateUser(email: string, password: string) {

        const user = await this.usersService.findByEmail(email);

        if(!user) throw new UnauthorizedException("User not found!");

        const isPasswordMatch = await argon2.verify(user.password, password);
        if(!isPasswordMatch) throw new UnauthorizedException("Invalid password!");
        //return to content of req.user
        return { id: user.id};

    }

    async validateJwtUser(userId: string):Promise<CurrentUser>{

        /*
        // Promise<CurrentUser> 的作用：
        // 1. 强制函数必须返回 CurrentUser 类型（编译期约束）
        // 2. 防止函数误 return null / 少字段 / 错结构
        // 3. 不影响运行时，也不保证不会 throw

        */

        const user = await this.usersService.findById(userId);
        if(!user) throw new UnauthorizedException("User not found!");

        //return {id: user.id, email: user.email, role: user.role}
        const currentUser: CurrentUser = {id: user.id, email: user.email, role: user.role}
        return currentUser;
     

    }

    async validateRefreshToken(userId: string, refreshToken: string) {
        
        try {
            const payload = await this.jwtService.verifyAsync(refreshToken, this.verifyRefreshTokenConfig);
            const jti = payload.jti;  

            const stored = await this.prisma.refreshToken.findUnique({
                where:{id: jti},
            })

            if(!stored || stored.expiresAt < new Date()){
                throw new UnauthorizedException("Invalid or expired refresh token");
            }

            const isMatch = await argon2.verify(stored.token, refreshToken);
            if(!isMatch) throw new UnauthorizedException("Invalid refresh token");

            return {id:userId, jti}
            

        } catch (error) {
            if(error instanceof UnauthorizedException){
                throw error;
            };

            throw error;
        };

              
    }
    
    
    sanitizeUser(user:User) {
        const { password, ...rest } = user;
        return rest;
    }
}

