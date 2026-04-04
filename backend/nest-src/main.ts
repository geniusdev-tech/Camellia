import 'dotenv/config';
import 'reflect-metadata';
import { Logger } from 'nestjs-pino';
import { NestFactory } from '@nestjs/core';
import helmet from 'helmet';
import { AppModule } from './app.module';
import { AppConfig, parseEnv } from './common/config/env.schema';

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
}

void bootstrap();
