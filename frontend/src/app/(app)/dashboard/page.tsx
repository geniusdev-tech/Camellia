'use client'

import Link from 'next/link'
import { useMemo } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  ActivitySquare,
  ArrowRight,
  Bookmark,
  Flame,
  FolderGit2,
  Globe2,
  Heart,
  Lightbulb,
  MessageCircle,
  Repeat2,
  ShieldCheck,
  UserPlus,
  Users,
} from 'lucide-react'
import { StatsBar } from '@/components/features/StatsBar'
import { socialAPI } from '@/lib/api'
import type { SocialFeedPost } from '@/lib/types'

const areas = [
  { href: '/repository', title: 'Repositório', icon: FolderGit2 },
  { href: '/teams', title: 'Times', icon: Users },
  { href: '/ops', title: 'Operações', icon: ActivitySquare },
  { href: '/catalog', title: 'Catálogo', icon: Globe2 },
]

export default function DashboardPage() {
  const qc = useQueryClient()

  const feedQuery = useQuery({
    queryKey: ['social', 'feed'],
    queryFn: socialAPI.feed,
    staleTime: 15_000,
  })

  const sidebarQuery = useQuery({
    queryKey: ['social', 'sidebar'],
    queryFn: socialAPI.sidebar,
    staleTime: 30_000,
  })

  const invalidateSocial = () => {
    qc.invalidateQueries({ queryKey: ['social', 'feed'] })
    qc.invalidateQueries({ queryKey: ['social', 'sidebar'] })
  }

  const reactMutation = useMutation({
    mutationFn: ({ postId, reactionType }: { postId: string; reactionType: 'like' | 'insight' | 'celebrate' }) =>
      socialAPI.react(postId, reactionType),
    onSuccess: invalidateSocial,
  })

  const bookmarkMutation = useMutation({
    mutationFn: (postId: string) => socialAPI.bookmarkToggle(postId),
    onSuccess: invalidateSocial,
  })

  const repostMutation = useMutation({
    mutationFn: (postId: string) => socialAPI.repostToggle(postId),
    onSuccess: invalidateSocial,
  })

  const commentMutation = useMutation({
    mutationFn: (postId: string) => socialAPI.comment(postId, 'Feedback positivo no feed.'),
    onSuccess: invalidateSocial,
  })

  const communityMutation = useMutation({
    mutationFn: (communityId: string) => socialAPI.communityToggle(communityId),
    onSuccess: invalidateSocial,
  })

  const posts = feedQuery.data?.posts ?? []
  const communities = sidebarQuery.data?.communities ?? []
  const trends = sidebarQuery.data?.trends ?? []
  const suggestedUsers = sidebarQuery.data?.suggestedUsers ?? []

  const fallbackPosts = useMemo<SocialFeedPost[]>(
    () =>
      areas.map((area, idx) => ({
        id: `fallback-${area.href}`,
        createdAt: new Date(Date.now() - idx * 60_000).toISOString(),
        content: `Atualização no módulo ${area.title}.`,
        release: {
          id: `fallback-release-${idx}`,
          packageName: area.title.toLowerCase(),
          packageVersion: '1.0.0',
          releaseChannel: 'stable',
          deploymentEnv: 'prod',
          status: 'published',
        },
        author: { id: 'system', email: 'system@gatestack.local' },
        stats: {
          reactions: { like: 0, insight: 0, celebrate: 0 },
          comments: 0,
          reposts: 0,
          bookmarks: 0,
        },
        viewer: {
          reactionType: null,
          bookmarked: false,
          reposted: false,
        },
      })),
    [],
  )

  const visiblePosts = posts.length ? posts : fallbackPosts

  return (
    <div className="social-page">
      <section className="social-hero">
        <p className="text-xs font-mono uppercase tracking-[0.2em] text-cyan-300">Feed Principal</p>
        <h1 className="mt-2 text-3xl font-bold leading-tight text-white">Feed de releases, times e operações</h1>
        <p className="mt-2 max-w-3xl text-sm text-gray-400">
          Atividade social real conectada ao backend: comunidades, tendências, reações e bookmarks.
        </p>
      </section>

      <StatsBar />

      <section className="mt-6 social-layout">
        <aside className="space-y-4">
          <div className="social-side-card backdrop-blur">
            <p className="text-xs font-semibold uppercase tracking-widest text-gray-500">Comunidades</p>
            <div className="mt-3 space-y-2">
              {communities.map((community) => (
                <button
                  key={community.id}
                  onClick={() => communityMutation.mutate(community.id)}
                  className={`flex w-full items-center justify-between rounded-2xl px-3 py-2 text-sm ${
                    community.joined ? 'bg-primary-600/20 text-primary-100' : 'bg-white/5 text-gray-200'
                  }`}
                >
                  <span className="truncate">{community.name}</span>
                  <span className="rounded-full bg-white/15 px-2 py-0.5 text-[10px]">{community.members}</span>
                </button>
              ))}
              {!communities.length ? <div className="text-xs text-gray-500">Sem comunidades.</div> : null}
            </div>
          </div>

          <div className="social-side-card backdrop-blur">
            <p className="text-xs font-semibold uppercase tracking-widest text-gray-500">Atalhos</p>
            <div className="mt-3 space-y-2">
              <Link href="/repository" className="social-link">
                Ver repositório
              </Link>
              <Link href="/ops" className="social-link">
                Ver operações
              </Link>
            </div>
          </div>
        </aside>

        <main className="space-y-4">
          {visiblePosts.map((post) => (
            <article key={post.id} className="rounded-3xl border border-white/10 bg-dark-900/60 p-5 backdrop-blur">
              <div className="flex items-start justify-between gap-4">
                <div className="flex items-start gap-3">
                  <div className="mt-0.5 flex h-11 w-11 items-center justify-center rounded-2xl bg-gradient-to-br from-cyan-500/30 to-green-400/20 text-cyan-200">
                    <FolderGit2 className="h-5 w-5" />
                  </div>
                  <div>
                    <p className="text-xs uppercase tracking-widest text-gray-500">Atualização</p>
                    <h3 className="mt-1 text-lg font-semibold text-white">
                      {post.release.packageName}@{post.release.packageVersion}
                    </h3>
                    <p className="mt-1 text-sm text-gray-400">{post.content}</p>
                    <p className="mt-1 text-xs text-gray-500">
                      {post.release.releaseChannel} · {post.release.deploymentEnv} · {post.release.status}
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => bookmarkMutation.mutate(post.id)}
                  className={`rounded-full p-2 ${
                    post.viewer.bookmarked ? 'text-emerald-300 bg-emerald-400/10' : 'text-gray-500 hover:bg-white/10 hover:text-white'
                  }`}
                >
                  <Bookmark className="h-4 w-4" />
                </button>
              </div>

              <div className="mt-4 flex items-center gap-4 text-xs text-gray-400">
                <button
                  onClick={() => reactMutation.mutate({ postId: post.id, reactionType: 'like' })}
                  className={`inline-flex items-center gap-1 ${post.viewer.reactionType === 'like' ? 'text-rose-300' : ''}`}
                >
                  <Heart className="h-3.5 w-3.5" /> {post.stats.reactions.like}
                </button>
                <button
                  onClick={() => reactMutation.mutate({ postId: post.id, reactionType: 'insight' })}
                  className={`inline-flex items-center gap-1 ${post.viewer.reactionType === 'insight' ? 'text-cyan-300' : ''}`}
                >
                  <Lightbulb className="h-3.5 w-3.5" /> {post.stats.reactions.insight}
                </button>
                <button
                  onClick={() => commentMutation.mutate(post.id)}
                  className="inline-flex items-center gap-1"
                >
                  <MessageCircle className="h-3.5 w-3.5" /> {post.stats.comments}
                </button>
                <button
                  onClick={() => repostMutation.mutate(post.id)}
                  className={`inline-flex items-center gap-1 ${post.viewer.reposted ? 'text-cyan-300' : ''}`}
                >
                  <Repeat2 className="h-3.5 w-3.5" /> {post.stats.reposts}
                </button>
                <span className="ml-auto text-[11px] text-gray-500">
                  {new Date(post.createdAt).toLocaleString('pt-BR')}
                </span>
              </div>
            </article>
          ))}
        </main>

        <aside className="space-y-4">
          <div className="social-side-card backdrop-blur">
            <div className="flex items-center gap-2">
              <Flame className="h-4 w-4 text-orange-300" />
              <p className="text-xs font-semibold uppercase tracking-widest text-gray-500">Tendências</p>
            </div>
            <div className="mt-3 space-y-2">
              {trends.map((trend) => (
                <button key={trend.tag} className="flex w-full items-center justify-between rounded-2xl bg-white/5 px-3 py-2 text-sm text-gray-200 hover:bg-white/10">
                  {trend.tag}
                  <span className="text-xs text-gray-500">{trend.count}</span>
                </button>
              ))}
              {!trends.length ? <div className="text-xs text-gray-500">Sem tendências calculadas.</div> : null}
            </div>
          </div>

          <div className="social-side-card backdrop-blur">
            <p className="text-xs font-semibold uppercase tracking-widest text-gray-500">Pessoas sugeridas</p>
            <div className="mt-3 space-y-3">
              {suggestedUsers.map((user) => (
                <div key={user.id} className="flex items-center justify-between rounded-2xl bg-white/5 px-3 py-2">
                  <div>
                    <p className="text-sm text-white">{user.email}</p>
                    <p className="text-xs text-gray-500">{user.role}</p>
                  </div>
                  <button className="rounded-xl bg-primary-500/20 px-2 py-1 text-xs text-primary-200">
                    <UserPlus className="h-3.5 w-3.5" />
                  </button>
                </div>
              ))}
              {!suggestedUsers.length ? <div className="text-xs text-gray-500">Sem sugestões no momento.</div> : null}
            </div>
          </div>

          <Link
            href="/teams"
            className="flex items-center justify-between rounded-3xl border border-emerald-400/20 bg-emerald-400/10 px-4 py-3 text-sm text-emerald-100"
          >
            <span className="inline-flex items-center gap-2">
              <ShieldCheck className="h-4 w-4" />
              Gerenciar equipes
            </span>
            <ArrowRight className="h-4 w-4" />
          </Link>
        </aside>
      </section>

      <section className="mt-6 grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {areas.map(({ href, title, icon: Icon }) => (
          <Link
            key={`quick-${href}`}
            href={href}
            className="group social-side-card rounded-2xl px-4 py-3 transition hover:border-cyan-400/40 hover:bg-dark-900/80"
          >
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-cyan-500/15 text-cyan-300">
                <Icon className="h-4 w-4" />
              </div>
              <div>
                <p className="text-sm font-medium text-white">{title}</p>
                <p className="text-xs text-gray-500">Entrar</p>
              </div>
            </div>
          </Link>
        ))}
      </section>
    </div>
  )
}
