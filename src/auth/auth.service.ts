import { BadRequestException, Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';

import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './entities/user.entity';
import * as bcrypt from "bcryptjs"
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';
import { LoginResponse } from './interfaces/login-response.interface';
import { CreateUserDto, LoginDto, RegisterUserDto } from './dto';

@Injectable()
export class AuthService {


  constructor
    (
      @InjectModel(User.name)
      private userModel: Model<User>,
      private jwtService: JwtService
    ) { }


  async create(createUserDto: CreateUserDto): Promise<User> {

    try {

      const { password, ...userData } = createUserDto;

      const newUser = new this.userModel(
        {
          ...userData,
          password: bcrypt.hashSync(password, 10),
        }
      );

      await newUser.save();
      const { password: _, ...user } = newUser.toJSON()
      return user;

    } catch (error) {
      if (error.code === 11000) {
        throw new BadRequestException(`${createUserDto.email} already exists!`)
      }
      throw new InternalServerErrorException("Something terrible happen :O 🤯")
    }

  }

  async register(registerUserDto: RegisterUserDto): Promise<LoginResponse> {

    const user = await this.create(registerUserDto);

    return {
      user,
      token: this.generateJwt({ id: user._id })
    }

  }

  async login(loginDto: LoginDto): Promise<LoginResponse> {

    const { email, password } = loginDto;

    const user = await this.userModel.findOne({ email: email });
    if (!user) {
      throw new UnauthorizedException('Email or Password incorrect')
    }
    if (!bcrypt.compareSync(password, user.password)) {
      throw new UnauthorizedException('Email or Password incorrect')
    }

    const { password: _, ...rest } = user.toJSON()

    return {
      user: rest,
      token: this.generateJwt({ id: user.id })
    }

  }

  chekToken(user: User): LoginResponse {
    return {
      user,
      token: this.generateJwt({ id: user._id })
    }

  }


  private generateJwt(payload: JwtPayload): string {
    const token = this.jwtService.sign(payload)
    return token;
  }


  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  async findUserById(id: string) {
    const user = await this.userModel.findById(id);
    const { password, ...res } = user.toJSON();
    return res;
  }


}
