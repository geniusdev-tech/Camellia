import { InjectQueue } from '@nestjs/bullmq';
import { Injectable, Optional } from '@nestjs/common';
import { Queue } from 'bullmq';
import { PinoLogger } from 'nestjs-pino';
import { parseEnv } from '../../common/config/env.schema';

@Injectable()
export class QueueService {
  private readonly env = parseEnv(process.env);
  private warnedQueueDisabled = false;
  private warnedQueueUnavailable = false;

  constructor(
    private readonly logger: PinoLogger,
    @Optional() @InjectQueue('release-jobs') private readonly releaseQueue?: Queue,
  ) {}

  private async enqueueJob(name: string, payload: Record<string, unknown>, attempts = 3): Promise<void> {
    if (!this.env.QUEUE_ENABLED) {
      if (!this.warnedQueueDisabled) {
        this.warnedQueueDisabled = true;
        this.logger.warn('QUEUE_ENABLED=false; queue jobs are disabled (fail-open mode)');
      }
      return;
    }

    if (!this.releaseQueue) {
      if (!this.warnedQueueUnavailable) {
        this.warnedQueueUnavailable = true;
        this.logger.warn('Queue provider unavailable; skipping enqueue (fail-open mode)');
      }
      return;
    }

    try {
      await this.releaseQueue.add(name, payload, {
        attempts,
        backoff: { type: 'exponential', delay: 1000 },
        removeOnFail: attempts > 1 ? 500 : false,
      });
    } catch (error) {
      if (!this.warnedQueueUnavailable) {
        this.warnedQueueUnavailable = true;
        this.logger.warn(
          { err: error instanceof Error ? error.message : String(error), job: name },
          'Queue enqueue failed; continuing without background processing (fail-open mode)',
        );
      }
    }
  }

  async enqueueScan(releaseId: string): Promise<void> {
    await this.enqueueJob('scan-release', { releaseId }, 3);
  }

  async enqueuePublish(releaseId: string): Promise<void> {
    await this.enqueueJob('publish-release', { releaseId }, 3);
  }

  async enqueueRollback(releaseId: string, targetReleaseId: string): Promise<void> {
    await this.enqueueJob('rollback-release', { releaseId, targetReleaseId }, 3);
  }

  async enqueueDeadLetter(jobName: string, payload: Record<string, unknown>, errorMessage: string): Promise<void> {
    await this.enqueueJob('release-dlq', { jobName, payload, errorMessage }, 1);
  }
}
