import { CanActivate, ExecutionContext, Injectable } from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import { Role } from "@prisma/client";
import { ROLES_KEY } from "../decorators/roles.decorator";


@Injectable()
export class RolesGuard implements CanActivate {
    //The constructor injects the Reflector helper class, 
    // which is provided by NestJS to read metadata attached to route handlers or classes (controllers).
    constructor(private reflector: Reflector){}
    //This is the core method required by the guard. It receives the ExecutionContext (which contains 
    // details about the current request) and must return a boolean (true to allow the request, false to block it).
    canActivate(context: ExecutionContext):boolean{
        
        const requiredRoles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY,[
            
            //Uses the reflector to look up the allowed roles based on the ROLES_KEY. 
            //getAllAndOverride will look at the method level first (context.getHandler()), 
            //and if nothing is found, it falls back to the controller class level (context.getClass()).
            //
            context.getHandler(),
            context.getClass(),
        ]);

        if(!requiredRoles) return true;

        //Converts the generic execution context into an HTTP context to extract the standard request object, 
        // and then destructures the user object from it (usually populated earlier by an authentication guard/passport).
        const {user} = context.switchToHttp().getRequest();
        return requiredRoles.includes(user.role);

        //return requiredRoles.some(role => user.role === role)



        //当有10000个角色，可以选用最优0(1)
        // const role = new Set(requiredRoles);
        // return role.has(user.role);
    }
}

//当系统变大，我们不再检查 user.role，而是检查 user.permissions。而且一个用户可能会有多个角色（user.roles）。
// import { CanActivate, ExecutionContext, Injectable } from "@nestjs/common";
// import { Reflector } from "@nestjs/core";
// // 1. 改变装饰器：从原来的 ROLES_KEY 变成 PERMISSIONS_KEY
// import { PERMISSIONS_KEY } from "../decorators/permissions.decorator"; 

// @Injectable()
// export class PermissionsGuard implements CanActivate {
//     constructor(private reflector: Reflector) {}

//     async canActivate(context: ExecutionContext): Promise<boolean> {
//         // 2. 获取接口定义研究所需的权限，例如 ['product.delete']
//         const requiredPermissions = this.reflector.getAllAndOverride<string[]>(PERMISSIONS_KEY, [
//             context.getHandler(),
//             context.getClass(),
//         ]);

//         // 如果接口没有设置权限限制，直接放行
//         if (!requiredPermissions) return true;

//         const request = context.switchToHttp().getRequest();
//         const user = request.user; // 假设在 AuthGuard 中已经把 user 注入到了 request

//         if (!user) return false;

//         /**
//          * 【大型企业级 RBAC 的数据结构】
//          * 此时的 user 对象通常在登录时就已经扁平化（Flatten）查出了权限集：
//          * user = {
//          * id: 1,
//          * roles: ['STAFF', 'SUPPORT'],
//          * permissions: ['product.edit', 'order.view', 'order.refund'] 
//          * }
//          */

//         // 3. 核心校验逻辑：检查用户拥有的权限是否满足接口所需的全部/部分权限
//         // 这里用 Set 做你之前提到的 O(1) 优化
//         const userPermissionSet = new Set(user.permissions);
        
//         // 必须包含接口所需的所有权限 (Every)
//         return requiredPermissions.every(permission => userPermissionSet.has(permission));
        
//         // 或者满足其中一个即可 (Some)，取决于你的业务设计：
//         // return requiredPermissions.some(permission => userPermissionSet.has(permission));
//     }
// }