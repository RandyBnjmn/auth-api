import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Request } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto, LoginDto, RegisterUserDto } from './dto';
import { AuthGuard } from './guards/auth.guard';
import { LoginResponse } from './interfaces/login-response.interface';
import { User } from './entities/user.entity';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) { }

  @Post()
  @UseGuards(AuthGuard)
  create(@Body() createUserDto: CreateUserDto) {
    return this.authService.create(createUserDto);
  }

  @Post('/register')
  register(@Body() registerUserDto: RegisterUserDto) {
    return this.authService.register(registerUserDto);
  }
  @Post("/login")
  login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto)
  }


  @UseGuards(AuthGuard)
  @Get()
  findAll(@Request() req: Request) {
    const user = req['user']
    return this.authService.findAll()
  }

  @Get("/check-token")
  @UseGuards(AuthGuard)

  checkToken(@Request() req: Request): LoginResponse {
    const user = req['user'] as User;
    return this.authService.chekToken(user)

  }
}
