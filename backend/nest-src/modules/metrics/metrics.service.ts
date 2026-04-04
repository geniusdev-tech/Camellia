import { Injectable } from '@nestjs/common';
import { Counter, Histogram, Registry, collectDefaultMetrics } from 'prom-client';

@Injectable()
export class MetricsService {
  private readonly registry = new Registry();
  private readonly httpCounter: Counter<string>;
  private readonly httpDuration: Histogram<string>;

  constructor() {
    collectDefaultMetrics({ register: this.registry, prefix: 'gatestack_' });

    this.httpCounter = new Counter({
      name: 'gatestack_http_requests_total',
      help: 'Total HTTP requests',
      labelNames: ['method', 'route', 'status_code'],
      registers: [this.registry],
    });

    this.httpDuration = new Histogram({
      name: 'gatestack_http_request_duration_ms',
      help: 'HTTP request duration in milliseconds',
      labelNames: ['method', 'route', 'status_code'],
      buckets: [5, 10, 25, 50, 100, 250, 500, 1000, 2500],
      registers: [this.registry],
    });
  }

  observeRequest(method: string, route: string, statusCode: number, durationMs: number): void {
    const labels = { method, route, status_code: String(statusCode) };
    this.httpCounter.inc(labels);
    this.httpDuration.observe(labels, durationMs);
  }

  async metrics(): Promise<string> {
    return this.registry.metrics();
  }

  contentType(): string {
    return this.registry.contentType;
  }
}
