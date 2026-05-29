import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class LocalAuthGuard extends AuthGuard('local') {}

// Purpose of this code:
// It creates a custom, strongly-typed Authentication Guard (LocalAuthGuard) by extending NestJS Passport's 
// built-in AuthGuard. It protects login routes by intercepting incoming requests and triggering 
// the 'local' passport strategy (username/password verification) before allowing the request to reach the controller.
//在 NestJS 中创建一个自定义的、强类型的身份验证守卫（LocalAuthGuard），专门用来保护登录路由