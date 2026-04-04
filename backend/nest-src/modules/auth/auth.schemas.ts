import { z } from 'zod';

export const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(10),
});

export type LoginInput = z.infer<typeof loginSchema>;

export const registerSchema = loginSchema.extend({
  password: loginSchema.shape.password.min(10),
});

export type RegisterInput = z.infer<typeof registerSchema>;
