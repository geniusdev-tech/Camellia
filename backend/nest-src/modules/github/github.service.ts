import { ForbiddenException, Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import axios from 'axios';
import { PrismaService } from '../../prisma/prisma.service';
import { parseEnv } from '../../common/config/env.schema';
import { openSecret } from '../../common/security/secret-crypto';

@Injectable()
export class GithubService {
  private readonly logger = new Logger(GithubService.name);
  private readonly env = parseEnv(process.env);

  constructor(private prisma: PrismaService) {}

  async syncUserRepositories(userId: string) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user || !user.githubToken) {
      throw new UnauthorizedException('User has not linked a GitHub account or token is missing');
    }
    const decryptedToken = openSecret(user.githubToken, this.env.JWT_SECRET) || user.githubToken;

    try {
      const response = await axios.get('https://api.github.com/user/repos?visibility=public&sort=updated&per_page=30', {
        headers: {
          Authorization: `Bearer ${decryptedToken}`,
          Accept: 'application/vnd.github.v3+json',
        },
      });

      const repos = response.data;
      
      // Upsert repos in our DB
      const syncedRepos = [];
      for (const repo of repos) {
        const synced = await this.prisma.gitHubRepository.upsert({
          where: {
            userId_githubId: {
              userId: user.id,
              githubId: repo.id,
            },
          },
          update: {
            name: repo.name,
            fullName: repo.full_name,
            description: repo.description,
            htmlUrl: repo.html_url,
            language: repo.language,
            stargazers: repo.stargazers_count,
            forks: repo.forks_count,
          },
          create: {
            githubId: repo.id,
            userId: user.id,
            name: repo.name,
            fullName: repo.full_name,
            description: repo.description,
            htmlUrl: repo.html_url,
            language: repo.language,
            stargazers: repo.stargazers_count,
            forks: repo.forks_count,
          },
        });
        syncedRepos.push(synced);
      }

      return syncedRepos;
    } catch (error) {
      const status = axios.isAxiosError(error) ? error.response?.status : undefined;
      this.logger.error(`Failed to sync GitHub repos for user ${userId}. status=${status ?? 'unknown'}`);
      if (status === 401 || status === 403) {
        throw new ForbiddenException('GitHub token inválido ou sem permissão para listar repositórios');
      }
      throw new Error('Falha ao sincronizar repositórios do GitHub');
    }
  }

  async getUserRepositories(userId: string) {
    // Return from DB
    return this.prisma.gitHubRepository.findMany({
      where: { userId },
      orderBy: { dbUpdatedAt: 'desc' },
    });
  }
}
