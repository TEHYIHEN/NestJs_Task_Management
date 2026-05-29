import { SetMetadata } from '@nestjs/common';
import { Role } from '@prisma/client';

// Define the metadata key name
// The Guard will use this key to read role permissions
export const ROLES_KEY = 'roles';

// Create a Roles decorator
// Accepts one or multiple roles
// Example: @Roles(Role.ADMIN)
// NestJS stores the roles inside metadata
export const Roles = (...roles: Role[]) => SetMetadata(ROLES_KEY, roles);

// @Roles(Role.ADMIN)
//        ↓
// SetMetadata('roles', [ADMIN]) 
//        ↓
// Guard 读取 'roles'
//        ↓
// 检查当前用户是不是 ADMIN
//        ↓
// 允许/拒绝访问