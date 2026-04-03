import { Request, Response, NextFunction } from 'express';
import { v4 as uuidv4 } from 'uuid';

class MetricsRegistry {
  private counters: Record<string, number> = {};
  private latenciesMs: Record<string, number[]> = {};

  record(method: string, route: string, statusCode: number, durationMs: number) {
    const key = `${method} ${route} ${statusCode}`;
    this.counters[key] = (this.counters[key] || 0) + 1;
    const latencyKey = `${method} ${route}`;
    if (!this.latenciesMs[latencyKey]) {
      this.latenciesMs[latencyKey] = [];
    }
    this.latenciesMs[latencyKey].push(durationMs);
  }

  snapshot() {
    const latencyMs: Record<string, any> = {};
    for (const [key, values] of Object.entries(this.latenciesMs)) {
      latencyMs[key] = {
        count: values.length,
        avg: values.length ? Math.round((values.reduce((a, b) => a + b, 0) / values.length) * 100) / 100 : 0,
        max: values.length ? Math.max(...values) : 0,
      };
    }
    return {
      requests: { ...this.counters },
      latency_ms: latencyMs,
    };
  }

  reset() {
    this.counters = {};
    this.latenciesMs = {};
  }
}

export const metricsRegistry = new MetricsRegistry();

export const requestObservability = (req: Request, res: Response, next: NextFunction) => {
  const requestId = req.header('X-Request-Id') || uuidv4();
  req.headers['X-Request-Id'] = requestId;
  const start = process.hrtime();

  res.on('finish', () => {
    const diff = process.hrtime(start);
    const durationMs = Math.round((diff[0] * 1e3 + diff[1] * 1e-6) * 100) / 100;
    const route = req.route ? req.route.path : req.path;
    metricsRegistry.record(req.method, route, res.statusCode, durationMs);
    res.setHeader('X-Response-Time-Ms', durationMs.toString());
    res.setHeader('X-Request-Id', requestId);
  });

  next();
};
