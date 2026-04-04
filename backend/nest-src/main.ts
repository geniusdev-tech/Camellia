import 'dotenv/config';
import 'reflect-metadata';
import { Logger } from 'nestjs-pino';
import { NestFactory } from '@nestjs/core';
import helmet from 'helmet';
import { AppModule } from './app.module';
import { AppConfig, parseEnv } from './common/config/env.schema';
import { execSync } from 'child_process';

async function runMigrations(): Promise<void> {
  const maxRetries = 10;
  const retryDelayMs = 1000;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      console.log('[Database] Running migrations...');
      execSync('npm run prisma:migrate:deploy', { stdio: 'inherit' });
      console.log('[Database] Migrations completed successfully');
      return;
    } catch (error) {
      if (attempt === maxRetries) {
        console.error('[Database] Failed to run migrations after', maxRetries, 'attempts');
        throw error;
      }
      console.warn(`[Database] Failed to run migrations (attempt ${attempt}/${maxRetries}), retrying in ${retryDelayMs}ms...`);
      await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
    }
  }
}

async function bootstrap(): Promise<void> {
  const env: AppConfig = parseEnv(process.env);
  
  // Run migrations before creating the app
  await runMigrations();

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
}

void bootstrap();
