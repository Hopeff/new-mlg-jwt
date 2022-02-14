const UserModel = require('../models/user_models')
const bcrypt = require('bcrypt')
const tokenService = require('./token-service')
const UserDto = require('../dtos/user-dto')
 const uuid = require('uuid');
const mailService = require('./mail-service');
const ApiError = require('../exeptions/api-error');

class UserService{
    async registration(email,password){
        const candidate = await UserModel.findOne({email})
         if (candidate) {
             throw ApiError.BadRequest(`почта ${email} уже занят`);
         }
        const hashPassword = await bcrypt.hash(password,3);
        const activationLink = uuid.v4 ();
        const user = await UserModel.create({email,password: hashPassword,activationLink})
        await mailService.sendActivationMail(email,`${process.env.API_URL}/api/activate/${activationLink}`);

        const userDto = new UserDto(user); // id , email, active
        const tokens = tokenService.generateTokens({...userDto});
        await tokenService.saveToken(userDto.id, tokens.refreshToken);

        return{...tokens, user:userDto}
    }
    async activate(activationLink){
        const user = await UserModel.findOne({activationLink})
        if(!user) {
            throw ApiError.BadRequest(`Анкорект активэтион линк`);
        }
        user.isActivated = true;
        await user.save();
    }
    async login(email, password){
        const user = await UserModel.findOne({email})
        if(!user){
            throw ApiError.BadRequest('вы тут никто')
        }
        const isPassEquals = await bcrypt.compare(password, user.password);
        if(!isPassEquals){
            throw ApiError.BadRequest('меняй пароль')
        }
        const userDto = new UserDto(user);
        const tokens = tokenService.generateTokens({...userDto});
        await tokenService.saveToken(userDto.id, tokens.refreshToken);
        return{...tokens, user:userDto}
    }
    async logout(refreshToken) {
        const token = await tokenService.removeToken(refreshToken);
        return token;
    }
    async refresh(refreshToken){
        const userData=tokenService.validateRefreshToken(refreshToken);
        const tokenFromDb = await tokenService.findToken(refreshToken);
        const user = await UserModel.findById(userData.id)
        const userDto = new UserDto(user);
        const tokens = tokenService.generateTokens({...userDto});
        await tokenService.saveToken(userDto.id, tokens.refreshToken);

        return{...tokens, user:userDto}

    }
}

module.exports = new UserService();