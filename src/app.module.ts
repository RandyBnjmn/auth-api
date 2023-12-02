import { Module } from '@nestjs/common';

import { AuthModule } from './auth/auth.module';
import { MongooseModule } from '@nestjs/mongoose';
import { ConfigModule } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';

@Module({
  imports: [
    ConfigModule.forRoot(),
    AuthModule,
    MongooseModule.forRoot(process.env.MONGO_URI),

    JwtModule.register({
      global: true,
      secret: process.env.JWT_SECRET,
      signOptions: { expiresIn: '1h' }
    })
  ],
  controllers: [],
  providers: [],
})
export class AppModule { }
