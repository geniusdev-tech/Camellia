import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {
  async onModuleInit(): Promise<void> {
    const maxRetries = 30;
    const retryDelayMs = 1000;

    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        await this.$connect();
        console.log('[PrismaService] Connected to database successfully');
        return;
      } catch (error) {
        if (attempt === maxRetries) {
          console.error('[PrismaService] Failed to connect to database after', maxRetries, 'attempts');
          throw error;
        }
        console.warn(`[PrismaService] Failed to connect (attempt ${attempt}/${maxRetries}), retrying in ${retryDelayMs}ms...`);
        await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
      }
    }
  }

  async onModuleDestroy(): Promise<void> {
    await this.$disconnect();
  }
}
