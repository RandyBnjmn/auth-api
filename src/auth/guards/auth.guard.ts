import { JwtService } from '@nestjs/jwt';
import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { Observable } from 'rxjs';
import { JwtPayload } from '../interfaces/jwt-payload.interface';
import { AuthService } from '../auth.service';

@Injectable()
export class AuthGuard implements CanActivate {

  constructor(private jwtServices: JwtService, private authservice: AuthService) {

  }
  async canActivate(
    context: ExecutionContext,
  ): Promise<boolean> {

    const request = context.switchToHttp().getRequest();
    const token = this.extracTokenFromHeader(request);
    console.log(token);
    if (!token) {
      throw new UnauthorizedException()
    }

    try {

      const payload = await this.jwtServices.verifyAsync<JwtPayload>(
        token,
        {
          secret: process.env.JWT_SECRET
        }
      )
      const usuario = await this.authservice.findUserById(payload.id);
      if (!usuario) {
        throw new UnauthorizedException("User does not exists");
      }
      if (!usuario.isActive) {
        throw new UnauthorizedException("User is not active")
      }

      console.log({ usuario });

      request['user'] = usuario


    } catch (error) {
      throw new UnauthorizedException()
    }


    return true;


  }
  private extracTokenFromHeader(request: Request) {

    const [type, token] = request.headers['authorization']?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined


  }
}
