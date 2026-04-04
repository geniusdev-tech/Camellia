import { Injectable, NotFoundException } from '@nestjs/common';
import { Prisma, ReactionType } from '@prisma/client';
import { PrismaService } from '../../prisma/prisma.service';
import { CreateCommentInput, SetReactionInput } from './social.schemas';

type FeedPost = {
  id: string;
  createdAt: string;
  content: string;
  release: {
    id: string;
    packageName: string;
    packageVersion: string;
    releaseChannel: string;
    deploymentEnv: string;
    status: string;
  };
  author: { id: string; email: string } | null;
  stats: {
    reactions: Record<ReactionType, number>;
    comments: number;
    reposts: number;
    bookmarks: number;
  };
  viewer: {
    reactionType: ReactionType | null;
    bookmarked: boolean;
    reposted: boolean;
  };
};

@Injectable()
export class SocialService {
  constructor(private readonly prisma: PrismaService) {}

  async getFeed(userId: string): Promise<{ posts: FeedPost[] }> {
    await this.ensureCommunitiesSeed();
    await this.syncPostsFromReleases();

    const posts = await this.prisma.socialPost.findMany({
      orderBy: { createdAt: 'desc' },
      take: 40,
      include: {
        release: true,
        author: { select: { id: true, email: true } },
      },
    });

    const postIds = posts.map((post) => post.id);
    if (!postIds.length) return { posts: [] };

    const [reactionRows, commentRows, repostRows, bookmarkRows, viewerReactions, viewerBookmarks, viewerReposts] =
      await Promise.all([
        this.prisma.socialReaction.groupBy({
          by: ['postId', 'reactionType'],
          where: { postId: { in: postIds } },
          _count: { _all: true },
        }),
        this.prisma.socialComment.groupBy({
          by: ['postId'],
          where: { postId: { in: postIds } },
          _count: { _all: true },
        }),
        this.prisma.socialRepost.groupBy({
          by: ['postId'],
          where: { postId: { in: postIds } },
          _count: { _all: true },
        }),
        this.prisma.socialBookmark.groupBy({
          by: ['postId'],
          where: { postId: { in: postIds } },
          _count: { _all: true },
        }),
        this.prisma.socialReaction.findMany({
          where: { userId, postId: { in: postIds } },
          select: { postId: true, reactionType: true },
        }),
        this.prisma.socialBookmark.findMany({
          where: { userId, postId: { in: postIds } },
          select: { postId: true },
        }),
        this.prisma.socialRepost.findMany({
          where: { userId, postId: { in: postIds } },
          select: { postId: true },
        }),
      ]);

    const baseReactionStats: Record<ReactionType, number> = {
      like: 0,
      insight: 0,
      celebrate: 0,
    };

    const reactionsByPost = new Map<string, Record<ReactionType, number>>();
    for (const row of reactionRows) {
      const current = reactionsByPost.get(row.postId) ?? { ...baseReactionStats };
      current[row.reactionType] = row._count._all;
      reactionsByPost.set(row.postId, current);
    }

    const commentsByPost = new Map(commentRows.map((row) => [row.postId, row._count._all]));
    const repostsByPost = new Map(repostRows.map((row) => [row.postId, row._count._all]));
    const bookmarksByPost = new Map(bookmarkRows.map((row) => [row.postId, row._count._all]));
    const viewerReactionByPost = new Map(viewerReactions.map((row) => [row.postId, row.reactionType]));
    const viewerBookmarksSet = new Set(viewerBookmarks.map((row) => row.postId));
    const viewerRepostsSet = new Set(viewerReposts.map((row) => row.postId));

    return {
      posts: posts.map((post) => ({
        id: post.id,
        createdAt: post.createdAt.toISOString(),
        content:
          post.content ||
          `Nova release ${post.release.packageName}@${post.release.packageVersion} (${post.release.releaseChannel}/${post.release.deploymentEnv}).`,
        release: {
          id: post.release.id,
          packageName: post.release.packageName,
          packageVersion: post.release.packageVersion,
          releaseChannel: post.release.releaseChannel,
          deploymentEnv: post.release.deploymentEnv,
          status: post.release.status,
        },
        author: post.author ? { id: post.author.id, email: post.author.email } : null,
        stats: {
          reactions: reactionsByPost.get(post.id) ?? { ...baseReactionStats },
          comments: commentsByPost.get(post.id) ?? 0,
          reposts: repostsByPost.get(post.id) ?? 0,
          bookmarks: bookmarksByPost.get(post.id) ?? 0,
        },
        viewer: {
          reactionType: viewerReactionByPost.get(post.id) ?? null,
          bookmarked: viewerBookmarksSet.has(post.id),
          reposted: viewerRepostsSet.has(post.id),
        },
      })),
    };
  }

  async getSidebar(userId: string) {
    await this.ensureCommunitiesSeed();

    const [communities, memberships, releases, users] = await Promise.all([
      this.prisma.socialCommunity.findMany({
        orderBy: { createdAt: 'asc' },
        include: { _count: { select: { members: true } } },
      }),
      this.prisma.socialCommunityMember.findMany({
        where: { userId },
        select: { communityId: true },
      }),
      this.prisma.release.findMany({
        orderBy: { createdAt: 'desc' },
        take: 120,
        select: { packageName: true },
      }),
      this.prisma.user.findMany({
        where: { id: { not: userId } },
        orderBy: { createdAt: 'desc' },
        take: 6,
        select: { id: true, email: true, role: true },
      }),
    ]);

    const trendsCount = new Map<string, number>();
    for (const release of releases) {
      const hashtag = `#${release.packageName.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`;
      trendsCount.set(hashtag, (trendsCount.get(hashtag) ?? 0) + 1);
    }

    const trends = [...trendsCount.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([tag, count]) => ({ tag, count }));

    const joined = new Set(memberships.map((membership) => membership.communityId));

    return {
      communities: communities.map((community) => ({
        id: community.id,
        slug: community.slug,
        name: community.name,
        description: community.description,
        members: community._count.members,
        joined: joined.has(community.id),
      })),
      trends,
      suggestedUsers: users.map((user) => ({
        id: user.id,
        email: user.email,
        role: user.role,
      })),
    };
  }

  async setReaction(postId: string, userId: string, payload: SetReactionInput) {
    await this.ensurePostExists(postId);

    const reaction = await this.prisma.socialReaction.upsert({
      where: { postId_userId: { postId, userId } },
      update: { reactionType: payload.reactionType },
      create: { postId, userId, reactionType: payload.reactionType },
    });

    return { postId, reactionType: reaction.reactionType };
  }

  async addComment(postId: string, userId: string, payload: CreateCommentInput) {
    await this.ensurePostExists(postId);
    const comment = await this.prisma.socialComment.create({
      data: { postId, userId, text: payload.text.trim() },
      select: { id: true, text: true, createdAt: true },
    });
    return {
      id: comment.id,
      text: comment.text,
      createdAt: comment.createdAt.toISOString(),
    };
  }

  async toggleBookmark(postId: string, userId: string) {
    await this.ensurePostExists(postId);
    const existing = await this.prisma.socialBookmark.findUnique({
      where: { postId_userId: { postId, userId } },
      select: { id: true },
    });

    if (existing) {
      await this.prisma.socialBookmark.delete({ where: { postId_userId: { postId, userId } } });
      return { postId, bookmarked: false };
    }

    await this.prisma.socialBookmark.create({ data: { postId, userId } });
    return { postId, bookmarked: true };
  }

  async toggleRepost(postId: string, userId: string) {
    await this.ensurePostExists(postId);
    const existing = await this.prisma.socialRepost.findUnique({
      where: { postId_userId: { postId, userId } },
      select: { id: true },
    });

    if (existing) {
      await this.prisma.socialRepost.delete({ where: { postId_userId: { postId, userId } } });
      return { postId, reposted: false };
    }

    await this.prisma.socialRepost.create({ data: { postId, userId } });
    return { postId, reposted: true };
  }

  async toggleCommunityMembership(communityId: string, userId: string) {
    const community = await this.prisma.socialCommunity.findUnique({
      where: { id: communityId },
      select: { id: true },
    });

    if (!community) throw new NotFoundException('Community not found');

    const existing = await this.prisma.socialCommunityMember.findUnique({
      where: { communityId_userId: { communityId, userId } },
      select: { id: true },
    });

    if (existing) {
      await this.prisma.socialCommunityMember.delete({ where: { communityId_userId: { communityId, userId } } });
      return { communityId, joined: false };
    }

    await this.prisma.socialCommunityMember.create({ data: { communityId, userId } });
    return { communityId, joined: true };
  }

  private async ensurePostExists(postId: string) {
    const post = await this.prisma.socialPost.findUnique({ where: { id: postId }, select: { id: true } });
    if (!post) throw new NotFoundException('Post not found');
  }

  private async ensureCommunitiesSeed() {
    const count = await this.prisma.socialCommunity.count();
    if (count > 0) return;

    const defaults: Array<Prisma.SocialCommunityCreateManyInput> = [
      {
        slug: 'security-watch',
        name: 'Security Watch',
        description: 'Triagem contínua de segurança e compliance.',
      },
      {
        slug: 'release-ops',
        name: 'Release Ops',
        description: 'Publicação, rollback e estabilidade operacional.',
      },
      {
        slug: 'team-hub',
        name: 'Team Hub',
        description: 'Colaboração entre times e governança de acesso.',
      },
    ];

    await this.prisma.socialCommunity.createMany({
      data: defaults,
      skipDuplicates: true,
    });
  }

  private async syncPostsFromReleases() {
    const releases = await this.prisma.release.findMany({
      orderBy: { createdAt: 'desc' },
      take: 200,
      select: {
        id: true,
        packageName: true,
        packageVersion: true,
        releaseChannel: true,
        deploymentEnv: true,
      },
    });

    if (!releases.length) return;

    const existing = await this.prisma.socialPost.findMany({
      where: { releaseId: { in: releases.map((release) => release.id) } },
      select: { releaseId: true },
    });
    const existingSet = new Set(existing.map((row) => row.releaseId));

    const missing = releases
      .filter((release) => !existingSet.has(release.id))
      .map((release): Prisma.SocialPostCreateManyInput => ({
        releaseId: release.id,
        content: `Nova release ${release.packageName}@${release.packageVersion} (${release.releaseChannel}/${release.deploymentEnv}).`,
      }));

    if (missing.length) {
      await this.prisma.socialPost.createMany({
        data: missing,
        skipDuplicates: true,
      });
    }
  }
}
