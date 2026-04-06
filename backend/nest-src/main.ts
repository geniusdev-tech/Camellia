import 'dotenv/config';
import 'reflect-metadata';
import './common/config/bootstrap-env';
import { Logger } from 'nestjs-pino';
import { NestFactory } from '@nestjs/core';
import helmet from 'helmet';
import { AppModule } from './app.module';
import { AppConfig, parseEnv } from './common/config/env.schema';
import { execSync } from 'child_process';
import { markDbReady } from './common/state/db-readiness';

async function runMigrations(logger: Logger): Promise<void> {
  const retryDelayMs = 5000;
  let attempt = 0;

  for (;;) {
    attempt += 1;
    try {
      logger.log(`[Database] Running migrations (attempt ${attempt})...`);
      execSync('npx prisma migrate deploy', { stdio: 'inherit' });
      logger.log('[Database] Migrations completed successfully');
      return;
    } catch {
      logger.warn(`[Database] Failed to run migrations (attempt ${attempt}), retrying in ${retryDelayMs}ms...`);
      await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
    }
  }
}

async function bootstrap(): Promise<void> {
  const env: AppConfig = parseEnv(process.env);

  const app = await NestFactory.create(AppModule, {
    bufferLogs: true,
  });

  const logger = app.get(Logger);
  app.useLogger(logger);
  app.use(helmet());
  app.enableShutdownHooks();

  app.enableCors({
    origin: env.ALLOWED_ORIGIN.split(',').map((item) => item.trim()).filter(Boolean),
    credentials: true,
  });

  await app.listen(env.PORT, env.HOST);
  logger.log(`GateStack backend listening on http://${env.HOST}:${env.PORT}`);

  // Run migrations in background after server is up so healthcheck responds immediately
  runMigrations(logger).then(() => {
    markDbReady();
  }).catch((err) => {
    logger.error('[Database] Background migration error:', err);
  });
}

void bootstrap();
