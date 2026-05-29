import { IsEmail, IsString, Length, Matches, MinLength } from 'class-validator'

export class RegisterDto{
    
    @IsEmail()
    email!: string;

    @IsString()
    @MinLength(6, {message:"Password at least 6 characters"})
    @Matches(/[A-Z]/, {message:"Password at least one uppercase letter"})
    @Matches(/[a-z]/, {message:"Password at least one lowercase letter"})
    @Matches(/[0-9]/, {message:"Password at least one number"})
    @Matches(/[!@#$%^&*(),.?":{}|<>]/, {message:"Password need at least one special character"})
    password!: string;

    @IsString()
    @Length(2, 50, {message:"Name must be between 2 to 50 characters"})
    /*
    \p{L} = international letter
    \p{N} = international number  example: 一二三，roma 123
    u     = unicode , without it cannot detect p{L} and p{N}
    \-_.  = symbol, example: user.name, user-name
    /^ and $/  = start and end
    (?: ......) = non-capturing group
    +     = one or more time
    *     = those () can 0 or more time  
    */
    @Matches(/^[\p{L}\p{N}\-_.]+(?: [\p{L}\p{N}\-_.]+)*$/u)
    name!: string;


}