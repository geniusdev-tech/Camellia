import { Body, Controller, Get, Param, Post, Req, UnauthorizedException, UseGuards, UsePipes } from '@nestjs/common';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { ZodValidationPipe } from '../../common/pipes/zod-validation.pipe';
import { SocialService } from './social.service';
import {
  communityIdParamSchema,
  createCommentSchema,
  postIdParamSchema,
  setReactionSchema,
  type CommunityIdParam,
  type CreateCommentInput,
  type PostIdParam,
  type SetReactionInput,
} from './social.schemas';

type AuthRequest = { user?: { sub?: unknown } };

@Controller('api/social')
@UseGuards(JwtAuthGuard, RolesGuard)
@Roles('admin', 'writer', 'reader')
export class SocialController {
  constructor(private readonly socialService: SocialService) {}

  @Get('feed')
  async feed(@Req() req: AuthRequest) {
    const userId = this.getUserId(req);
    const payload = await this.socialService.getFeed(userId);
    return { success: true, ...payload };
  }

  @Get('sidebar')
  async sidebar(@Req() req: AuthRequest) {
    const userId = this.getUserId(req);
    const payload = await this.socialService.getSidebar(userId);
    return { success: true, ...payload };
  }

  @Post('posts/:postId/reaction')
  @UsePipes(new ZodValidationPipe(setReactionSchema))
  async react(
    @Req() req: AuthRequest,
    @Param(new ZodValidationPipe(postIdParamSchema)) params: PostIdParam,
    @Body() body: SetReactionInput,
  ) {
    const userId = this.getUserId(req);
    const payload = await this.socialService.setReaction(params.postId, userId, body);
    return { success: true, ...payload };
  }

  @Post('posts/:postId/comment')
  @UsePipes(new ZodValidationPipe(createCommentSchema))
  async comment(
    @Req() req: AuthRequest,
    @Param(new ZodValidationPipe(postIdParamSchema)) params: PostIdParam,
    @Body() body: CreateCommentInput,
  ) {
    const userId = this.getUserId(req);
    const comment = await this.socialService.addComment(params.postId, userId, body);
    return { success: true, comment };
  }

  @Post('posts/:postId/bookmark')
  async bookmark(@Req() req: AuthRequest, @Param(new ZodValidationPipe(postIdParamSchema)) params: PostIdParam) {
    const userId = this.getUserId(req);
    const payload = await this.socialService.toggleBookmark(params.postId, userId);
    return { success: true, ...payload };
  }

  @Post('posts/:postId/repost')
  async repost(@Req() req: AuthRequest, @Param(new ZodValidationPipe(postIdParamSchema)) params: PostIdParam) {
    const userId = this.getUserId(req);
    const payload = await this.socialService.toggleRepost(params.postId, userId);
    return { success: true, ...payload };
  }

  @Post('communities/:communityId/toggle')
  async toggleCommunity(
    @Req() req: AuthRequest,
    @Param(new ZodValidationPipe(communityIdParamSchema)) params: CommunityIdParam,
  ) {
    const userId = this.getUserId(req);
    const payload = await this.socialService.toggleCommunityMembership(params.communityId, userId);
    return { success: true, ...payload };
  }

  private getUserId(req: AuthRequest): string {
    const raw = req.user?.sub;
    if (typeof raw !== 'string' || !raw.trim()) {
      throw new UnauthorizedException('Authenticated user id not found');
    }
    return raw;
  }
}
