import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(PrismaService.name);

  async onModuleInit(): Promise<void> {
    // Connect in background so we don't block NestJS startup.
    // The health endpoint responds immediately; the DB retries happen behind the scenes.
    this.connectWithRetry().catch((err) => {
      this.logger.error('[PrismaService] Background DB connection failed permanently', err);
    });
  }

  private async connectWithRetry(): Promise<void> {
    const maxRetries = 30;
    const retryDelayMs = 2000;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        await this.$connect();
        this.logger.log('[PrismaService] Connected to database successfully');
        return;
      } catch (error) {
        if (attempt === maxRetries) {
          this.logger.error(`[PrismaService] Failed to connect after ${maxRetries} attempts`);
          throw error;
        }
        this.logger.warn(`[PrismaService] Connection attempt ${attempt}/${maxRetries} failed, retrying in ${retryDelayMs}ms...`);
        await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
      }
    }
  }

  async onModuleDestroy(): Promise<void> {
    await this.$disconnect();
  }
}
