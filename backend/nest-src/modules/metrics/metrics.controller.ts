import { Controller, Get, Header, Res, UseGuards } from '@nestjs/common';
import { MetricsTokenGuard } from '../../common/guards/metrics-token.guard';
import { MetricsService } from './metrics.service';

@Controller()
export class MetricsController {
  constructor(private readonly metricsService: MetricsService) {}

  @Get('metrics')
  @UseGuards(MetricsTokenGuard)
  @Header('Content-Type', 'text/plain')
  async getMetrics(@Res() res: { setHeader: (name: string, value: string) => void; send: (body: string) => void }): Promise<void> {
    res.setHeader('Content-Type', this.metricsService.contentType());
    res.send(await this.metricsService.metrics());
  }
}
