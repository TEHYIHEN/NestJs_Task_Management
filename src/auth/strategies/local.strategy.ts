import { Injectable, UnauthorizedException } from "@nestjs/common";
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';
import { AuthService } from "../auth.service";

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy, 'local') {

    constructor(private authService: AuthService){
        super({ usernameField: "email" });
        /* usernameField 默认会username作为登入条件， 在nodemodule/passport-local/stragey js 有注明 */
        //passwordField: 'password'  //因为默认是password,不写也行
    }

    /* 
    validate use to check and confirm the data receive from super();
    查看AuthService,它最后返回 user.id
  */
    validate(email: string, password: string){

        if(password === "") {
            throw new UnauthorizedException("Please Provide The Password");
        }

        return this.authService.validateUser(email, password);
  
  }
    

}