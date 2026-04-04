import { z } from 'zod';

export const postIdParamSchema = z.object({
  postId: z.string().uuid(),
});

export type PostIdParam = z.infer<typeof postIdParamSchema>;

export const communityIdParamSchema = z.object({
  communityId: z.string().uuid(),
});

export type CommunityIdParam = z.infer<typeof communityIdParamSchema>;

export const setReactionSchema = z.object({
  reactionType: z.enum(['like', 'insight', 'celebrate']),
});

export type SetReactionInput = z.infer<typeof setReactionSchema>;

export const createCommentSchema = z.object({
  text: z.string().min(1).max(500),
});

export type CreateCommentInput = z.infer<typeof createCommentSchema>;
