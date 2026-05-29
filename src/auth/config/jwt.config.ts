import { registerAs } from "@nestjs/config";
import { JwtModuleOptions } from "@nestjs/jwt";
import { StringValue } from "ms"

export default registerAs("jwt", ():JwtModuleOptions =>({

    secret: process.env.JWT_SECRET,
    signOptions:{
        expiresIn: "process.env.JWT_EXPIRES_IN" as StringValue
    }
}))