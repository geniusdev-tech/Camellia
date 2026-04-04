import { ConflictException, Injectable, OnModuleInit, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import bcrypt from 'bcryptjs';
import { PrismaService } from '../../prisma/prisma.service';
import { parseEnv } from '../../common/config/env.schema';
import type { Role } from '../../common/decorators/roles.decorator';
import type { LoginInput } from './auth.schemas';
import type { RegisterInput } from './auth.schemas';

@Injectable()
export class AuthService implements OnModuleInit {
  private readonly env = parseEnv(process.env);

  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
  ) {}

  async register(payload: RegisterInput): Promise<{ accessToken: string }> {
    const normalizedEmail = payload.email.toLowerCase();
    const existing = await this.prisma.user.findUnique({ where: { email: normalizedEmail } });
    if (existing) {
      throw new ConflictException('Email already in use');
    }

    const passwordHash = await bcrypt.hash(payload.password, 12);
    const user = await this.prisma.user.create({
      data: {
        email: normalizedEmail,
        passwordHash,
        role: 'reader',
      },
    });

    const accessToken = await this.signToken({
      sub: user.id,
      email: user.email,
      role: user.role as Role,
    });

    return { accessToken };
  }

  async onModuleInit(): Promise<void> {
    const passwordHash = await bcrypt.hash(this.env.ADMIN_PASSWORD, 12);
    await this.prisma.user.upsert({
      where: { email: this.env.ADMIN_EMAIL.toLowerCase() },
      update: { passwordHash, role: 'admin' },
      create: { email: this.env.ADMIN_EMAIL.toLowerCase(), passwordHash, role: 'admin' },
    });
  }

  async login(payload: LoginInput): Promise<{ accessToken: string }> {
    const user = await this.prisma.user.findUnique({ where: { email: payload.email.toLowerCase() } });
    if (!user) throw new UnauthorizedException('Invalid credentials');

    const valid = await bcrypt.compare(payload.password, user.passwordHash);
    if (!valid) throw new UnauthorizedException('Invalid credentials');

    const accessToken = await this.signToken({
      sub: user.id,
      email: user.email,
      role: user.role as Role,
    });

    return { accessToken };
  }

  private signToken(payload: { sub: string; email: string; role: Role }) {
    return this.jwtService.signAsync(payload, {
      secret: this.env.JWT_SECRET,
      expiresIn: this.env.JWT_EXPIRES_IN,
    });
  }
}
