import { CanActivate, ExecutionContext, ForbiddenException, Injectable } from '@nestjs/common';
import { parseEnv } from '../config/env.schema';

@Injectable()
export class MetricsTokenGuard implements CanActivate {
  private readonly env = parseEnv(process.env);

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<{ headers: Record<string, string | undefined> }>();
    const metricsToken = String(request.headers['x-metrics-token'] || '');
    const authHeader = String(request.headers.authorization || '');
    const bearer = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
    const token = metricsToken || bearer;

    if (!token || token !== this.env.METRICS_TOKEN) {
      throw new ForbiddenException('Invalid metrics token');
    }
    return true;
  }
}
