import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { BullModule } from '@nestjs/bullmq';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { LoggerModule } from 'nestjs-pino';
import { HealthModule } from './modules/health/health.module';
import { ReleasesModule } from './modules/releases/releases.module';
import { MetricsModule } from './modules/metrics/metrics.module';
import { QueueModule } from './modules/queue/queue.module';
import { PrismaModule } from './prisma/prisma.module';
import { parseEnv } from './common/config/env.schema';
import { AuthModule } from './modules/auth/auth.module';
import { SocialModule } from './modules/social/social.module';
import { GithubModule } from './modules/github/github.module';

const env = parseEnv(process.env);

@Module({
  imports: [
    LoggerModule.forRoot({
      pinoHttp: {
        level: env.LOG_LEVEL,
        transport:
          env.NODE_ENV === 'development'
            ? {
                target: 'pino-pretty',
                options: { colorize: true, translateTime: 'SYS:standard' },
              }
            : undefined,
      },
    }),
    ...(
      env.QUEUE_ENABLED
        ? [
            BullModule.forRoot({
              connection: {
                host: env.REDIS_HOST,
                port: env.REDIS_PORT,
                password: env.REDIS_PASSWORD || undefined,
                // Avoid aggressive reconnect loops when Redis is down/misconfigured.
                maxRetriesPerRequest: 1,
                enableReadyCheck: false,
                retryStrategy: (times: number) => (times <= 2 ? Math.min(times * 500, 1000) : null),
              },
              defaultJobOptions: {
                removeOnComplete: 200,
                removeOnFail: 500,
                attempts: 3,
              },
            }),
          ]
        : []
    ),
    ThrottlerModule.forRoot([
      {
        ttl: env.THROTTLE_TTL * 1000,
        limit: env.THROTTLE_LIMIT,
      },
    ]),
    PrismaModule,
    AuthModule,
    HealthModule,
    ReleasesModule,
    SocialModule,
    GithubModule,
    MetricsModule,
    QueueModule,
  ],
  providers: [
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
  ],
})
export class AppModule {}
