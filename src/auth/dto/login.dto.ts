import { RegisterDto } from "./register.dto";
import { PickType } from "@nestjs/swagger"

export class LoginDto extends PickType(RegisterDto, ['email', 'password']){}