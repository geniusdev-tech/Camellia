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
    if (this.env.NODE_ENV === 'test') {
      return;
    }
    // Keep startup resilient: admin bootstrap runs in background.
    void this.initializeAdminWithRetry();
  }

  private async initializeAdminWithRetry(): Promise<void> {
    const maxRetries = 30;
    const retryDelayMs = 1000;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        const passwordHash = await bcrypt.hash(this.env.ADMIN_PASSWORD, 12);
        await this.prisma.user.upsert({
          where: { email: this.env.ADMIN_EMAIL.toLowerCase() },
          update: { passwordHash, role: 'admin' },
          create: { email: this.env.ADMIN_EMAIL.toLowerCase(), passwordHash, role: 'admin' },
        });
        console.log('[AuthService] Admin user initialized successfully');
        return;
      } catch (error) {
        if (attempt === maxRetries) {
          console.error('[AuthService] Failed to initialize admin user after', maxRetries, 'attempts:', error);
          return;
        }
        console.warn(`[AuthService] Failed to initialize admin user (attempt ${attempt}/${maxRetries}), retrying in ${retryDelayMs}ms...`);
        await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
      }
    }
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
