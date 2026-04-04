import { INestApplication } from '@nestjs/common';
import { APP_INTERCEPTOR, Reflector } from '@nestjs/core';
import { JwtModule } from '@nestjs/jwt';
import { Test } from '@nestjs/testing';
import { randomUUID } from 'node:crypto';
import type { ReleaseStatus, UserRole } from '@prisma/client';

type InMemoryUser = {
  id: string;
  email: string;
  passwordHash: string;
  role: UserRole;
};

type InMemoryRelease = {
  id: string;
  packageName: string;
  packageVersion: string;
  releaseChannel: 'alpha' | 'beta' | 'stable';
  deploymentEnv: 'dev' | 'staging' | 'prod';
  status: ReleaseStatus;
  maxCvss: number;
  complianceScore: number;
  riskScore: number;
  policyApproved: boolean;
  rollbackOfId: string | null;
  metadataJson: string | null;
  createdAt: Date;
  updatedAt: Date;
};

function createPrismaMock() {
  const users = new Map<string, InMemoryUser>();
  const releases = new Map<string, InMemoryRelease>();

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const prismaMock: any = {
    user: {
      async upsert(input: {
        where: { email: string };
        update: { passwordHash?: string; role?: UserRole };
        create: { email: string; passwordHash: string; role: UserRole };
      }) {
        const email = input.where.email.toLowerCase();
        const current = users.get(email);
        if (current) {
          const updated: InMemoryUser = {
            ...current,
            passwordHash: input.update.passwordHash ?? current.passwordHash,
            role: input.update.role ?? current.role,
          };
          users.set(email, updated);
          return updated;
        }

        const created: InMemoryUser = {
          id: randomUUID(),
          email,
          passwordHash: input.create.passwordHash,
          role: input.create.role,
        };
        users.set(email, created);
        return created;
      },
      async findUnique(input: { where: { email: string } }) {
        return users.get(input.where.email.toLowerCase()) ?? null;
      },
    },
    release: {
      async create(input: {
        data: {
          packageName: string;
          packageVersion: string;
          releaseChannel: 'alpha' | 'beta' | 'stable';
          deploymentEnv: 'dev' | 'staging' | 'prod';
          maxCvss: number;
          complianceScore: number;
          riskScore: number;
          metadataJson: string | null;
        };
      }) {
        const now = new Date();
        const created: InMemoryRelease = {
          id: randomUUID(),
          packageName: input.data.packageName,
          packageVersion: input.data.packageVersion,
          releaseChannel: input.data.releaseChannel,
          deploymentEnv: input.data.deploymentEnv,
          status: 'draft',
          maxCvss: input.data.maxCvss,
          complianceScore: input.data.complianceScore,
          riskScore: input.data.riskScore,
          policyApproved: false,
          rollbackOfId: null,
          metadataJson: input.data.metadataJson,
          createdAt: now,
          updatedAt: now,
        };
        releases.set(created.id, created);
        return created;
      },
      async findMany() {
        return [...releases.values()].sort((a, b) => b.createdAt.getTime() - a.createdAt.getTime());
      },
    },
  };

  return prismaMock;
}

export type E2eContext = {
  app: INestApplication;
};

export async function createE2eApp(): Promise<E2eContext> {
  process.env.NODE_ENV = 'test';
  process.env.HOST = '0.0.0.0';
  process.env.PORT = '5000';
  process.env.ALLOWED_ORIGIN = 'https://test.local';
  process.env.DATABASE_URL = 'postgresql://test:test@db:5432/testdb?schema=test';
  process.env.REDIS_HOST = 'redis';
  process.env.REDIS_PORT = '6379';
  process.env.REDIS_PASSWORD = 'test_redis_password';
  process.env.JWT_SECRET = 'test_secret_that_is_at_least_32_chars_long';
  process.env.JWT_EXPIRES_IN = '1h';
  process.env.ADMIN_EMAIL = 'admin@gatestack.local';
  process.env.ADMIN_PASSWORD = 'ChangeMeNow_12345';
  process.env.METRICS_TOKEN = 'test_metrics_token_123456';
  process.env.THROTTLE_TTL = '60';
  process.env.THROTTLE_LIMIT = '120';
  process.env.PUBLISH_MAX_CVSS = '7';
  process.env.LOG_LEVEL = 'error';

  const prismaMock = createPrismaMock();

  const [
    { PrismaService },
    { QueueService },
    { HealthController },
    { AuthController },
    { AuthService },
    { JwtAuthGuard },
    { RolesGuard },
    { ReleasesController },
    { ReleasesService },
    { MetricsController },
    { MetricsService },
    { MetricsTokenGuard },
    { MetricsInterceptor },
  ] = await Promise.all([
    import('../../nest-src/prisma/prisma.service'),
    import('../../nest-src/modules/queue/queue.service'),
    import('../../nest-src/modules/health/health.controller'),
    import('../../nest-src/modules/auth/auth.controller'),
    import('../../nest-src/modules/auth/auth.service'),
    import('../../nest-src/common/guards/jwt-auth.guard'),
    import('../../nest-src/common/guards/roles.guard'),
    import('../../nest-src/modules/releases/releases.controller'),
    import('../../nest-src/modules/releases/releases.service'),
    import('../../nest-src/modules/metrics/metrics.controller'),
    import('../../nest-src/modules/metrics/metrics.service'),
    import('../../nest-src/common/guards/metrics-token.guard'),
    import('../../nest-src/modules/metrics/metrics.interceptor'),
  ]);

  const moduleRef = await Test.createTestingModule({
    imports: [JwtModule.register({})],
    controllers: [HealthController, AuthController, ReleasesController, MetricsController],
    providers: [
      AuthService,
      JwtAuthGuard,
      RolesGuard,
      ReleasesService,
      MetricsService,
      MetricsTokenGuard,
      Reflector,
      {
        provide: APP_INTERCEPTOR,
        useClass: MetricsInterceptor,
      },
      {
        provide: PrismaService,
        useValue: prismaMock,
      },
      {
        provide: QueueService,
        useValue: {
          enqueueScan: async () => undefined,
          enqueuePublish: async () => undefined,
          enqueueRollback: async () => undefined,
          enqueueDeadLetter: async () => undefined,
        },
      },
    ],
  }).compile();

  const app = moduleRef.createNestApplication();
  await app.init();

  return { app };
}

export async function closeE2eApp(ctx: E2eContext): Promise<void> {
  await ctx.app.close();
}
