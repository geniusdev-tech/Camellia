import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { parseEnv } from '../config/env.schema';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  private readonly env = parseEnv(process.env);

  constructor(private readonly jwtService: JwtService) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<{ headers: Record<string, string | undefined>; user?: Record<string, unknown> }>();
    const header = String(request.headers.authorization || '');
    const token = header.startsWith('Bearer ') ? header.slice(7) : '';

    if (!token) throw new UnauthorizedException('Missing bearer token');

    try {
      const payload = this.jwtService.verify(token, { secret: this.env.JWT_SECRET }) as Record<string, unknown>;
      request.user = payload;
      return true;
    } catch {
      throw new UnauthorizedException('Invalid or expired token');
    }
  }
}
