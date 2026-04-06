import { Controller, Get } from '@nestjs/common';
import { isDbReady } from '../../common/state/db-readiness';

@Controller()
export class HealthController {
  @Get('health')
  health() {
    return {
      status: isDbReady() ? 'ok' : 'starting',
      service: 'gatestack-backend',
      timestamp: new Date().toISOString(),
      database: isDbReady() ? 'ready' : 'unavailable',
    };
  }
}
