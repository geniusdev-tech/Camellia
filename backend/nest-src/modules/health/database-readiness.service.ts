import { Injectable, OnModuleInit } from '@nestjs/common';
import { PrismaService } from './prisma.service';

@Injectable()
export class DatabaseReadinessService implements OnModuleInit {
  private ready = false;

  constructor(private prisma: PrismaService) {}

  async onModuleInit() {
    try {
      await this.prisma.$queryRaw`SELECT 1`;
      this.ready = true;
    } catch {
      this.ready = false;
    }
  }

  isReady(): boolean {
    return this.ready;
  }
}
