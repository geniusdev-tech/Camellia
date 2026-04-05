import { z } from 'zod';

const booleanFromEnv = z.preprocess((value) => {
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    if (['1', 'true', 'yes', 'on'].includes(normalized)) return true;
    if (['0', 'false', 'no', 'off'].includes(normalized)) return false;
  }
  return value;
}, z.boolean());

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  HOST: z.string().default('0.0.0.0'),
  PORT: z.coerce.number().int().positive().default(5000),
  ALLOWED_ORIGIN: z.string().min(1),
  DATABASE_URL: z.string().min(1),
  REDIS_HOST: z.string().default('redis'),
  REDIS_PORT: z.coerce.number().int().positive().default(6379),
  REDIS_PASSWORD: z.string().optional(),
  QUEUE_ENABLED: booleanFromEnv.default(false),
  QUEUE_WORKER_ENABLED: booleanFromEnv.default(false),
  JWT_SECRET: z.string().min(32),
  JWT_EXPIRES_IN: z.string().default('1h'),
  ADMIN_EMAIL: z.string().email(),
  ADMIN_PASSWORD: z.string().min(10),
  METRICS_TOKEN: z.string().min(16),
  THROTTLE_TTL: z.coerce.number().int().positive().default(60),
  THROTTLE_LIMIT: z.coerce.number().int().positive().default(120),
  PUBLISH_MAX_CVSS: z.coerce.number().min(0).max(10).default(7),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
  GITHUB_CLIENT_ID: z.string().optional(),
  GITHUB_CLIENT_SECRET: z.string().optional(),
  GITHUB_CALLBACK_URL: z.string().optional(),
}).superRefine((env, ctx) => {
  const githubValues = [env.GITHUB_CLIENT_ID, env.GITHUB_CLIENT_SECRET, env.GITHUB_CALLBACK_URL];
  const configuredCount = githubValues.filter((value) => Boolean(value && value.trim())).length;
  if (configuredCount > 0 && configuredCount < githubValues.length) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['GITHUB_CLIENT_ID'],
      message: 'Set GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET and GITHUB_CALLBACK_URL together',
    });
  }
});

export type AppConfig = z.infer<typeof envSchema>;

export function parseEnv(source: Record<string, unknown>): AppConfig {
  const result = envSchema.safeParse(source);
  if (!result.success) {
    const message = result.error.issues.map((issue) => `${issue.path.join('.')}: ${issue.message}`).join('; ');
    throw new Error(`Invalid environment configuration: ${message}`);
  }
  const env = result.data;
  if (env.NODE_ENV === 'production') {
    const origins = env.ALLOWED_ORIGIN.split(',').map((item) => item.trim());
    if (origins.includes('*')) {
      throw new Error('Invalid environment configuration: ALLOWED_ORIGIN cannot contain "*" in production');
    }
  }
  return env;
}
