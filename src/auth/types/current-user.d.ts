import { Role } from "@prisma/client";


export type CurrentUser = {

    id: string;
    email: string;
    role: Role;

}