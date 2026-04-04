import { Controller, Get } from '@nestjs/common';

@Controller()
export class HealthController {
  @Get('health')
  health() {
    return {
      status: 'ok',
      service: 'gatestack-backend',
      timestamp: new Date().toISOString(),
    };
  }
}
