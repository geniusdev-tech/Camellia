import { Controller, Get, Post, Req, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { GithubService } from './github.service';

@Controller('api/github')
@UseGuards(JwtAuthGuard)
export class GithubController {
  constructor(private readonly githubService: GithubService) {}

  @Get('repos')
  async getRepos(@Req() req: any) {
    const repos = await this.githubService.getUserRepositories(req.user.sub);
    return { success: true, count: repos.length, repos };
  }

  @Post('repos/sync')
  async syncRepos(@Req() req: any) {
    const repos = await this.githubService.syncUserRepositories(req.user.sub);
    return { success: true, count: repos.length, repos };
  }
}
