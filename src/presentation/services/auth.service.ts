import { bcryptAdapter, JwtAdapter } from "../../config";
import { UserModel } from "../../data";
import { CustomError, LoginUserDto, RegisterUserDto, UserEntity } from "../../domain";


export class AuthService {

    // DI
    constructor(){}

    public async registerUser(registerUserDto: RegisterUserDto) {

        const existUser = await UserModel.findOne({email: registerUserDto.email});
        if(existUser) throw CustomError.badRequest('Email already exist');

        try {
            const user = new UserModel(registerUserDto);
            
            // Encriptar contraseña
            user.password = bcryptAdapter.hash(registerUserDto.password);
            
            await user.save();
            // JWT <-- para mantener la autenticacion del usuario

            // Email de confirmación

            const {password, ...userEntity} = UserEntity.fromObject(user);
            
            return {
                user: userEntity,
                token: 'ABC'
            };
        } catch (error) {
            throw CustomError.internalServer(`${error}`);
        }

        return 'todo ok';
    }

    public async loginUser(loginUserDto: LoginUserDto) {

        const existUser = await UserModel.findOne({email: loginUserDto.email});
        if(!existUser) throw CustomError.badRequest(`User with email ${loginUserDto.email} is not register`);

        const isMatch = bcryptAdapter.compare(loginUserDto.password, existUser.password!);
        if(!isMatch) throw CustomError.badRequest('Password is not valid');

        const {password, ...userEntity} = UserEntity.fromObject(existUser);

        const token = await JwtAdapter.generateToken({id: existUser.id, email: existUser.email});
        if(!token) throw CustomError.internalServer('Token could not be created');
        
        return {
            user: userEntity,
            token: token,
        }  
    }
    
}