import { z } from 'zod';

export const createReleaseSchema = z.object({
  packageName: z.string().min(2).max(128).regex(/^[a-zA-Z0-9][a-zA-Z0-9._-]{1,127}$/),
  packageVersion: z.string().regex(/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$/),
  releaseChannel: z.enum(['alpha', 'beta', 'stable']).default('stable'),
  deploymentEnv: z.enum(['dev', 'staging', 'prod']).default('dev'),
  maxCvss: z.number().min(0).max(10).default(0),
  complianceScore: z.number().min(0).max(100).default(0),
  riskScore: z.number().min(0).max(100).default(100),
  metadata: z.record(z.string(), z.unknown()).optional(),
});

export type CreateReleaseInput = z.infer<typeof createReleaseSchema>;

export const releaseIdParamSchema = z.object({
  releaseId: z.string().uuid(),
});

export type ReleaseIdParam = z.infer<typeof releaseIdParamSchema>;

export const rollbackSchema = z.object({
  targetReleaseId: z.string().uuid(),
});

export type RollbackInput = z.infer<typeof rollbackSchema>;
