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

  private async fetchGithub<T>(path: string, token: string, params?: Record<string, string | number>) {
    const response = await axios.get<T>(`https://api.github.com${path}`, {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/vnd.github.v3+json',
      },
      params,
    });
    return response.data;
  }

  private async resolveGithubAccessToken(userId: string): Promise<string> {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user || !user.githubToken) {
      throw new UnauthorizedException('User has not linked a GitHub account or token is missing');
    }
    return openSecret(user.githubToken, this.env.JWT_SECRET) || user.githubToken;
  }

  async getUserProfile(userId: string) {
    const decryptedToken = await this.resolveGithubAccessToken(userId);

    try {
      const data = await this.fetchGithub<any>('/user', decryptedToken);
      return {
        githubId: data.id,
        login: data.login,
        name: data.name,
        avatarUrl: data.avatar_url,
        bio: data.bio,
        company: data.company,
        location: data.location,
        blog: data.blog,
        htmlUrl: data.html_url,
        followers: data.followers,
        following: data.following,
        publicRepos: data.public_repos,
      };
    } catch (error) {
      const status = axios.isAxiosError(error) ? error.response?.status : undefined;
      this.logger.error(`Failed to fetch GitHub profile for user ${userId}. status=${status ?? 'unknown'}`);
      if (status === 401 || status === 403) {
        throw new ForbiddenException('GitHub token inválido ou sem permissão para consultar perfil');
      }
      throw new Error('Falha ao buscar perfil do GitHub');
    }
  }

  async getDashboardData(
    userId: string,
    rawQuery: Record<string, unknown>,
  ): Promise<{
    tokenStatus: 'ok' | 'expired';
    sync: { lastSyncedAt: string | null; cachedRepos: number };
    profile: {
      githubId: number;
      login: string;
      name?: string | null;
      avatarUrl: string;
      bio?: string | null;
      company?: string | null;
      location?: string | null;
      blog?: string | null;
      htmlUrl: string;
      followers: number;
      following: number;
      publicRepos: number;
    };
    topRepositories: Array<{
      id: number;
      name: string;
      fullName: string;
      description?: string | null;
      htmlUrl: string;
      language?: string | null;
      stargazers: number;
      forks: number;
      updatedAt: string;
      openIssues: number;
      ownerLogin: string;
      ownerType: 'User' | 'Organization' | string;
      defaultBranch?: string | null;
      license?: string | null;
    }>;
    recentActivity: Array<{
      type: 'commit' | 'pull_request' | 'issue';
      repo: string;
      createdAt: string;
      title: string;
      url: string;
    }>;
    health: {
      languages: Array<{ language: string; count: number }>;
      reposWithoutDescription: number;
      reposWithoutLicense: number;
      reposWithOpenIssuesAboveThreshold: number;
      issuesThreshold: number;
    };
    security: {
      scannedRepos: number;
      withBranchProtection: number;
      withoutBranchProtection: number;
      reposWithDependabotAlerts: number | null;
      reposWithCodeScanningAlerts: number | null;
      dependabotAvailable: boolean;
      codeScanningAvailable: boolean;
    };
    quickActions: {
      githubProfileUrl: string;
      openPullRequestsUrl: string;
      createIssueUrl: string | null;
    };
  }> {
    const sortBy = String(rawQuery.sortBy || 'updated');
    const scope = String(rawQuery.scope || 'all');
    const issuesThreshold = Number(rawQuery.issuesThreshold || 10);
    const normalizedSort: 'stars' | 'updated' | 'forks' =
      sortBy === 'stars' || sortBy === 'forks' ? sortBy : 'updated';
    const normalizedScope: 'all' | 'owner' | 'org' =
      scope === 'owner' || scope === 'org' ? scope : 'all';
    const threshold = Number.isFinite(issuesThreshold) && issuesThreshold > 0 ? issuesThreshold : 10;

    const token = await this.resolveGithubAccessToken(userId);
    let profile: any;
    let repos: any[] = [];
    try {
      profile = await this.fetchGithub<any>('/user', token);
      repos = await this.fetchGithub<any[]>('/user/repos', token, {
        visibility: 'public',
        sort: 'updated',
        per_page: 100,
      });
    } catch (error) {
      const status = axios.isAxiosError(error) ? error.response?.status : undefined;
      if (status === 401 || status === 403) {
        throw new ForbiddenException('GitHub token expirado ou sem permissão');
      }
      throw error;
    }

    const scopedRepos = repos.filter((repo) => {
      if (normalizedScope === 'owner') return repo.owner?.type === 'User' && repo.owner?.login === profile.login;
      if (normalizedScope === 'org') return repo.owner?.type === 'Organization';
      return true;
    });

    const sortedRepos = [...scopedRepos].sort((a, b) => {
      if (normalizedSort === 'stars') return (b.stargazers_count || 0) - (a.stargazers_count || 0);
      if (normalizedSort === 'forks') return (b.forks_count || 0) - (a.forks_count || 0);
      return new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime();
    });

    const topRepositories = sortedRepos.slice(0, 8).map((repo) => ({
      id: repo.id,
      name: repo.name,
      fullName: repo.full_name,
      description: repo.description,
      htmlUrl: repo.html_url,
      language: repo.language,
      stargazers: repo.stargazers_count || 0,
      forks: repo.forks_count || 0,
      updatedAt: repo.updated_at,
      openIssues: repo.open_issues_count || 0,
      ownerLogin: repo.owner?.login || '',
      ownerType: repo.owner?.type || 'User',
      defaultBranch: repo.default_branch,
      license: repo.license?.spdx_id || repo.license?.name || null,
    }));

    const sevenDaysAgo = Date.now() - (7 * 24 * 60 * 60 * 1000);
    const events = await this.fetchGithub<any[]>(`/users/${encodeURIComponent(profile.login)}/events/public`, token, {
      per_page: 100,
    }).catch(() => []);

    const recentActivity = events
      .filter((event) => new Date(event.created_at).getTime() >= sevenDaysAgo)
      .flatMap((event) => {
        if (event.type === 'PushEvent') {
          const commits = Array.isArray(event.payload?.commits) ? event.payload.commits : [];
          return commits.slice(0, 2).map((commit: any) => ({
            type: 'commit' as const,
            repo: event.repo?.name || 'unknown',
            createdAt: event.created_at,
            title: commit.message || 'Commit',
            url: commit.url ? String(commit.url).replace('api.github.com/repos', 'github.com').replace('/commits/', '/commit/') : `https://github.com/${event.repo?.name}`,
          }));
        }
        if (event.type === 'PullRequestEvent') {
          const pr = event.payload?.pull_request;
          return [{
            type: 'pull_request' as const,
            repo: event.repo?.name || 'unknown',
            createdAt: event.created_at,
            title: pr?.title || 'Pull request',
            url: pr?.html_url || `https://github.com/${event.repo?.name}/pulls`,
          }];
        }
        if (event.type === 'IssuesEvent') {
          const issue = event.payload?.issue;
          return [{
            type: 'issue' as const,
            repo: event.repo?.name || 'unknown',
            createdAt: event.created_at,
            title: issue?.title || 'Issue',
            url: issue?.html_url || `https://github.com/${event.repo?.name}/issues`,
          }];
        }
        return [];
      })
      .slice(0, 12);

    const languageMap = new Map<string, number>();
    for (const repo of scopedRepos) {
      const language = repo.language || 'Unknown';
      languageMap.set(language, (languageMap.get(language) || 0) + 1);
    }
    const languages = [...languageMap.entries()]
      .map(([language, count]) => ({ language, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);

    const reposWithoutDescription = scopedRepos.filter((repo) => !repo.description || !String(repo.description).trim()).length;
    const reposWithoutLicense = scopedRepos.filter((repo) => !repo.license).length;
    const reposWithOpenIssuesAboveThreshold = scopedRepos.filter((repo) => (repo.open_issues_count || 0) > threshold).length;

    let withBranchProtection = 0;
    let withoutBranchProtection = 0;
    let reposWithDependabotAlerts = 0;
    let reposWithCodeScanningAlerts = 0;
    let dependabotAvailable = true;
    let codeScanningAvailable = true;

    for (const repo of topRepositories.slice(0, 6)) {
      try {
        const branch = await this.fetchGithub<any>(
          `/repos/${encodeURIComponent(repo.ownerLogin)}/${encodeURIComponent(repo.name)}/branches/${encodeURIComponent(repo.defaultBranch || 'main')}`,
          token,
        );
        if (branch?.protected) withBranchProtection += 1;
        else withoutBranchProtection += 1;
      } catch {
        withoutBranchProtection += 1;
      }

      if (dependabotAvailable) {
        try {
          const depResponse = await axios.get(
            `https://api.github.com/repos/${encodeURIComponent(repo.ownerLogin)}/${encodeURIComponent(repo.name)}/dependabot/alerts`,
            {
              headers: {
                Authorization: `Bearer ${token}`,
                Accept: 'application/vnd.github+json',
              },
              params: { state: 'open', per_page: 1 },
            },
          );
          if (Array.isArray(depResponse.data) && depResponse.data.length > 0) reposWithDependabotAlerts += 1;
        } catch (error) {
          const status = axios.isAxiosError(error) ? error.response?.status : undefined;
          if (status === 403 || status === 404) dependabotAvailable = false;
        }
      }

      if (codeScanningAvailable) {
        try {
          const codeResponse = await axios.get(
            `https://api.github.com/repos/${encodeURIComponent(repo.ownerLogin)}/${encodeURIComponent(repo.name)}/code-scanning/alerts`,
            {
              headers: {
                Authorization: `Bearer ${token}`,
                Accept: 'application/vnd.github+json',
              },
              params: { state: 'open', per_page: 1 },
            },
          );
          if (Array.isArray(codeResponse.data) && codeResponse.data.length > 0) reposWithCodeScanningAlerts += 1;
        } catch (error) {
          const status = axios.isAxiosError(error) ? error.response?.status : undefined;
          if (status === 403 || status === 404) codeScanningAvailable = false;
        }
      }
    }

    const cached = await this.prisma.gitHubRepository.findMany({
      where: { userId },
      orderBy: { dbUpdatedAt: 'desc' },
      take: 1,
    });

    const sync = {
      lastSyncedAt: cached[0]?.dbUpdatedAt?.toISOString?.() || null,
      cachedRepos: await this.prisma.gitHubRepository.count({ where: { userId } }),
    };

    const firstRepo = topRepositories[0];
    return {
      tokenStatus: 'ok',
      sync,
      profile: {
        githubId: profile.id,
        login: profile.login,
        name: profile.name,
        avatarUrl: profile.avatar_url,
        bio: profile.bio,
        company: profile.company,
        location: profile.location,
        blog: profile.blog,
        htmlUrl: profile.html_url,
        followers: profile.followers,
        following: profile.following,
        publicRepos: profile.public_repos,
      },
      topRepositories,
      recentActivity,
      health: {
        languages,
        reposWithoutDescription,
        reposWithoutLicense,
        reposWithOpenIssuesAboveThreshold,
        issuesThreshold: threshold,
      },
      security: {
        scannedRepos: Math.min(6, topRepositories.length),
        withBranchProtection,
        withoutBranchProtection,
        reposWithDependabotAlerts: dependabotAvailable ? reposWithDependabotAlerts : null,
        reposWithCodeScanningAlerts: codeScanningAvailable ? reposWithCodeScanningAlerts : null,
        dependabotAvailable,
        codeScanningAvailable,
      },
      quickActions: {
        githubProfileUrl: profile.html_url,
        openPullRequestsUrl: `https://github.com/pulls?q=is%3Apr+is%3Aopen+author%3A${encodeURIComponent(profile.login)}`,
        createIssueUrl: firstRepo ? `https://github.com/${firstRepo.fullName}/issues/new` : null,
      },
    };
  }

  async syncUserRepositories(userId: string) {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (!user) {
      throw new UnauthorizedException('User not found');
    }
    const decryptedToken = await this.resolveGithubAccessToken(userId);

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
