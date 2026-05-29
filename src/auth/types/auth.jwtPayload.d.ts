import { Role } from "@prisma/client";


export type AuthJwtPayload = {
  sub: string;   // user id
  email: string;
  role: Role;  // RBAC
  jti: string;   // refresh token id
};