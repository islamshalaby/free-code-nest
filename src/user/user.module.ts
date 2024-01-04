import { Module } from '@nestjs/common';
import { JwtStrategy } from 'src/auth/strategy';
import { UserController } from './user.controller';

@Module({
  providers: [JwtStrategy],
  controllers: [UserController],
})
export class UserModule {}
