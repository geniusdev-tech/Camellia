import { Module } from '@nestjs/common';
import { BullModule } from '@nestjs/bullmq';
import { parseEnv } from '../../common/config/env.schema';
import { QueueService } from './queue.service';
import { QueueProcessor } from './queue.processor';

const env = parseEnv(process.env);

@Module({
  imports: [
    ...(
      env.QUEUE_ENABLED
        ? [
            BullModule.registerQueue({
              name: 'release-jobs',
            }),
          ]
        : []
    ),
  ],
  providers: [QueueService, ...(env.QUEUE_ENABLED && env.QUEUE_WORKER_ENABLED ? [QueueProcessor] : [])],
  exports: [QueueService],
})
export class QueueModule {}
