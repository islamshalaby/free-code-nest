import {
  ForbiddenException,
  HttpException,
  HttpStatus,
  Injectable,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon2 from 'argon2';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private configService: ConfigService,
  ) {}
  async signUp(dto: AuthDto): Promise<{ access_token: string }> {
    const hash = await argon2.hash(dto.password);
    const user = await this.prisma.user
      .create({
        data: { email: dto.email, hash },
      })
      .catch((err) => {
        if (err.code === 'P2002') {
          throw new ForbiddenException('Email already exists');
        }
        throw new HttpException('Something went wrong', HttpStatus.BAD_REQUEST);
      });

    return this.signToken(user.id, user.email);
  }

  async signIn(dto: AuthDto): Promise<{ access_token: string }> {
    // find user by email
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
    });

    // throw error if user not found
    if (!user)
      throw new HttpException(
        'Invalid credentials',
        HttpStatus.NON_AUTHORITATIVE_INFORMATION,
      );

    // compare password
    const isMatch = await argon2.verify(user.hash, dto.password);

    // throw error if password not match
    if (!isMatch)
      throw new HttpException(
        'Invalid credentials',
        HttpStatus.NON_AUTHORITATIVE_INFORMATION,
      );

    return this.signToken(user.id, user.email);
  }

  async signToken(
    userId: number,
    email: string,
  ): Promise<{ access_token: string }> {
    const payload = {
      sub: userId,
      email,
    };

    const secret = this.configService.get<string>('JWT_SECRET');

    return {
      access_token: await this.jwt.signAsync(payload, {
        secret,
        expiresIn: '15m',
      }),
    };
  }
}
