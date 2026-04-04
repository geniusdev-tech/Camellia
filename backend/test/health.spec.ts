import { Test } from '@nestjs/testing';
import { HealthController } from '../nest-src/modules/health/health.controller';

describe('HealthController', () => {
  it('returns ok status', async () => {
    const moduleRef = await Test.createTestingModule({
      controllers: [HealthController],
    }).compile();

    const controller = moduleRef.get(HealthController);
    const response = controller.health() as { status: string };

    expect(response.status).toBe('ok');
  });
});
