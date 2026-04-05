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
    const retryDelayMs = 5000;
    let attempt = 0;

    for (;;) {
      attempt += 1;
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
        console.warn(`[AuthService] Failed to initialize admin user (attempt ${attempt}), retrying in ${retryDelayMs}ms...`, error);
        await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
      }
    }
  }

  async login(payload: LoginInput): Promise<{ accessToken: string }> {
    const user = await this.prisma.user.findUnique({ where: { email: payload.email.toLowerCase() } });
    if (!user || user.passwordHash === null) throw new UnauthorizedException('Invalid credentials');

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

  async validateGithubUser(profile: { githubId: string; email?: string; name?: string; avatarUrl?: string; githubToken: string }) {
    let user = await this.prisma.user.findFirst({
      where: {
        OR: [
          { githubId: profile.githubId },
          ...(profile.email ? [{ email: profile.email.toLowerCase() }] : []),
        ],
      },
    });

    if (user) {
      // Update existing user with latest github info
      user = await this.prisma.user.update({
        where: { id: user.id },
        data: {
          githubId: profile.githubId,
          name: profile.name || user.name,
          avatarUrl: profile.avatarUrl || user.avatarUrl,
          githubToken: profile.githubToken,
        },
      });
    } else {
      // Create new user. Since they might not have a public email, fallback to a dummy one if needed
      const fallbackEmail = profile.email || `${profile.githubId}@github.gatestack.local`;
      user = await this.prisma.user.create({
        data: {
          email: fallbackEmail.toLowerCase(),
          githubId: profile.githubId,
          name: profile.name,
          avatarUrl: profile.avatarUrl,
          githubToken: profile.githubToken,
          role: 'reader',
        },
      });
    }

    return user;
  }

  async githubLogin(user: any): Promise<{ accessToken: string }> {
    const accessToken = await this.signToken({
      sub: user.id,
      email: user.email,
      role: user.role as Role,
    });
    return { accessToken };
  }

  async getUserById(id: string) {
    const user = await this.prisma.user.findUnique({
      where: { id },
    });
    if (!user) {
      throw new UnauthorizedException('User not found');
    }
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { passwordHash: _ph, githubToken: _gt, ...safeUser } = user;
    return { ...safeUser, has_2fa: false };
  }
}
