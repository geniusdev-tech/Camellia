import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor,
} from '@nestjs/common';
import { Observable, finalize } from 'rxjs';
import { MetricsService } from './metrics.service';

@Injectable()
export class MetricsInterceptor implements NestInterceptor {
  constructor(private readonly metricsService: MetricsService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const request = context.switchToHttp().getRequest<{ method: string; route?: { path?: string }; path: string }>();
    const response = context.switchToHttp().getResponse<{ statusCode: number }>();
    const startedAt = process.hrtime.bigint();

    return next.handle().pipe(
      finalize(() => {
        const elapsedNs = process.hrtime.bigint() - startedAt;
        const durationMs = Number(elapsedNs / BigInt(1e6));
        const route = request.route?.path || request.path || 'unknown';
        this.metricsService.observeRequest(request.method, route, response.statusCode, durationMs);
      }),
    );
  }
}
