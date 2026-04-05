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
import { socialAPI, githubAPI } from '@/lib/api'
import type { GithubRepository, SocialFeedPost } from '@/lib/types'
import { useAuthStore } from '@/store/auth'

const areas = [
  { href: '/repository', title: 'Repositório', icon: FolderGit2 },
  { href: '/teams', title: 'Times', icon: Users },
  { href: '/ops', title: 'Operações', icon: ActivitySquare },
  { href: '/catalog', title: 'Catálogo', icon: Globe2 },
]

export default function DashboardPage() {
  const qc = useQueryClient()
  const { user } = useAuthStore()

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

  const reposQuery = useQuery({
    queryKey: ['github', 'repos'],
    queryFn: githubAPI.repos,
    enabled: !!user?.github_id || !!user?.githubId,
    staleTime: 60_000,
  })

  const syncReposMutation = useMutation({
    mutationFn: githubAPI.sync,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['github', 'repos'] })
    },
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
  const githubRepos = reposQuery.data?.repos ?? []

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
      {/* Hero */}
      <section className="glass rounded-2xl p-6 mb-6 animate-fade-up">
        <p className="text-xs font-mono uppercase tracking-[0.25em] text-cyan-400">Feed Principal</p>
        <h1 className="mt-2 text-2xl sm:text-3xl font-bold leading-tight text-white">
          Feed de releases, times e operações
        </h1>
        <p className="mt-2 max-w-3xl text-sm text-gray-500">
          Atividade social conectada ao backend: comunidades, tendências, reações e bookmarks.
        </p>
      </section>

      <StatsBar />

      {/* GitHub Repositories (Only if linked) */}
      {(user?.github_id || user?.githubId) && (
        <section className="mt-6 mb-6 animate-fade-up">
          <div className="flex items-center justify-between mb-4">
            <div>
              <p className="text-xs font-mono uppercase tracking-[0.2em] text-gray-500">Meus Repositórios</p>
              <h2 className="text-lg font-bold text-white mt-1">Sincronizados do GitHub</h2>
            </div>
            <button
              onClick={() => syncReposMutation.mutate()}
              disabled={syncReposMutation.isPending}
              className="flex items-center gap-2 rounded-xl bg-white/5 border border-white/10 px-3 py-1.5 text-sm text-gray-300 hover:bg-white/10 hover:text-white transition-all disabled:opacity-50"
            >
              <Repeat2 className={`h-4 w-4 ${syncReposMutation.isPending ? 'animate-spin' : ''}`} />
              Sincronizar
            </button>
          </div>

          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {reposQuery.isLoading && <p className="text-sm text-gray-500 p-4">Carregando seus repositórios...</p>}
            {!reposQuery.isLoading && githubRepos.length === 0 && (
              <p className="text-sm text-gray-500 p-4">Nenhum repositório encontrado ou sincronizado ainda.</p>
            )}
            {githubRepos.slice(0, 6).map((repo: GithubRepository) => (
              <a
                key={repo.id}
                href={repo.htmlUrl}
                target="_blank"
                rel="noreferrer"
                className="group flex flex-col justify-between glass rounded-2xl p-4 transition-all hover:border-cyan-400/20 hover:bg-white/5"
              >
                <div>
                  <div className="flex items-center gap-2 mb-2 text-cyan-400">
                    <FolderGit2 className="h-4 w-4" />
                    <span className="font-semibold truncate text-sm">{repo.name}</span>
                  </div>
                  <p className="text-xs text-gray-400 line-clamp-2 mt-1">
                    {repo.description || 'Sem descrição.'}
                  </p>
                </div>
                <div className="mt-4 flex items-center gap-4 text-xs text-gray-500">
                  {repo.language && (
                    <span className="flex items-center gap-1.5">
                      <span className="w-2 h-2 rounded-full bg-cyan-500/50 block"></span>
                      {repo.language}
                    </span>
                  )}
                  <span className="flex items-center gap-1">
                    <Heart className="h-3 w-3 text-rose-500/80" /> {repo.stargazers}
                  </span>
                </div>
              </a>
            ))}
          </div>
        </section>
      )}

      {/* Main Layout */}
      <section className="mt-6 social-layout">
        {/* Left Sidebar */}
        <aside className="space-y-4 animate-fade-up delay-100">
          <div className="glass rounded-2xl p-4">
            <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-gray-500">Comunidades</p>
            <div className="mt-3 space-y-1.5">
              {communities.map((community) => (
                <button
                  key={community.id}
                  onClick={() => communityMutation.mutate(community.id)}
                  className={`flex w-full items-center justify-between rounded-xl px-3 py-2 text-sm transition-all ${
                    community.joined
                      ? 'bg-cyan-400/8 text-cyan-200 border border-cyan-400/15'
                      : 'bg-white/3 text-gray-300 border border-transparent hover:bg-white/5'
                  }`}
                >
                  <span className="truncate">{community.name}</span>
                  <span className="rounded-full bg-white/10 px-2 py-0.5 text-[10px] text-gray-400">{community.members}</span>
                </button>
              ))}
              {!communities.length && <div className="text-xs text-gray-600">Sem comunidades.</div>}
            </div>
          </div>

          <div className="glass rounded-2xl p-4">
            <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-gray-500">Atalhos</p>
            <div className="mt-3 space-y-1.5">
              <Link href="/repository" className="social-link">Ver repositório</Link>
              <Link href="/ops" className="social-link">Ver operações</Link>
            </div>
          </div>
        </aside>

        {/* Feed */}
        <main className="space-y-4 animate-fade-up delay-200">
          {visiblePosts.map((post) => (
            <article key={post.id} className="glass rounded-2xl p-5 transition-all hover:border-white/10">
              <div className="flex items-start justify-between gap-4">
                <div className="flex items-start gap-3">
                  <div className="mt-0.5 flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-400/15 to-green-400/10 border border-white/5">
                    <FolderGit2 className="h-4.5 w-4.5 text-cyan-400" />
                  </div>
                  <div>
                    <p className="text-[10px] uppercase tracking-[0.2em] text-gray-500">Atualização</p>
                    <h3 className="mt-0.5 text-base font-semibold text-white">
                      {post.release.packageName}@{post.release.packageVersion}
                    </h3>
                    <p className="mt-1 text-sm text-gray-400">{post.content}</p>
                    <p className="mt-1 text-xs text-gray-600 font-mono">
                      {post.release.releaseChannel} · {post.release.deploymentEnv} · {post.release.status}
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => bookmarkMutation.mutate(post.id)}
                  className={`rounded-xl p-2 transition-all ${
                    post.viewer.bookmarked
                      ? 'text-green-400 bg-green-400/10'
                      : 'text-gray-600 hover:bg-white/5 hover:text-gray-300'
                  }`}
                >
                  <Bookmark className="h-4 w-4" />
                </button>
              </div>

              <div className="mt-4 flex items-center gap-5 text-xs text-gray-500">
                <button
                  onClick={() => reactMutation.mutate({ postId: post.id, reactionType: 'like' })}
                  className={`inline-flex items-center gap-1.5 transition-colors hover:text-rose-400 ${post.viewer.reactionType === 'like' ? 'text-rose-400' : ''}`}
                >
                  <Heart className="h-3.5 w-3.5" /> {post.stats.reactions.like}
                </button>
                <button
                  onClick={() => reactMutation.mutate({ postId: post.id, reactionType: 'insight' })}
                  className={`inline-flex items-center gap-1.5 transition-colors hover:text-cyan-400 ${post.viewer.reactionType === 'insight' ? 'text-cyan-400' : ''}`}
                >
                  <Lightbulb className="h-3.5 w-3.5" /> {post.stats.reactions.insight}
                </button>
                <button
                  onClick={() => commentMutation.mutate(post.id)}
                  className="inline-flex items-center gap-1.5 transition-colors hover:text-white"
                >
                  <MessageCircle className="h-3.5 w-3.5" /> {post.stats.comments}
                </button>
                <button
                  onClick={() => repostMutation.mutate(post.id)}
                  className={`inline-flex items-center gap-1.5 transition-colors hover:text-cyan-400 ${post.viewer.reposted ? 'text-cyan-400' : ''}`}
                >
                  <Repeat2 className="h-3.5 w-3.5" /> {post.stats.reposts}
                </button>
                <span className="ml-auto text-[11px] text-gray-600">
                  {new Date(post.createdAt).toLocaleString('pt-BR')}
                </span>
              </div>
            </article>
          ))}
        </main>

        {/* Right Sidebar */}
        <aside className="space-y-4 animate-fade-up delay-300">
          <div className="glass rounded-2xl p-4">
            <div className="flex items-center gap-2">
              <Flame className="h-4 w-4 text-orange-400" />
              <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-gray-500">Tendências</p>
            </div>
            <div className="mt-3 space-y-1.5">
              {trends.map((trend) => (
                <button key={trend.tag} className="flex w-full items-center justify-between rounded-xl bg-white/3 px-3 py-2 text-sm text-gray-300 hover:bg-white/5 transition-all">
                  {trend.tag}
                  <span className="text-xs text-gray-600">{trend.count}</span>
                </button>
              ))}
              {!trends.length && <div className="text-xs text-gray-600">Sem tendências calculadas.</div>}
            </div>
          </div>

          <div className="glass rounded-2xl p-4">
            <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-gray-500">Pessoas sugeridas</p>
            <div className="mt-3 space-y-2">
              {suggestedUsers.map((user) => (
                <div key={user.id} className="flex items-center justify-between rounded-xl bg-white/3 px-3 py-2">
                  <div>
                    <p className="text-sm text-white">{user.email}</p>
                    <p className="text-xs text-gray-600">{user.role}</p>
                  </div>
                  <button className="rounded-lg bg-cyan-400/10 border border-cyan-400/15 px-2 py-1 text-cyan-400 hover:bg-cyan-400/15 transition-all">
                    <UserPlus className="h-3.5 w-3.5" />
                  </button>
                </div>
              ))}
              {!suggestedUsers.length && <div className="text-xs text-gray-600">Sem sugestões no momento.</div>}
            </div>
          </div>

          <Link
            href="/teams"
            className="flex items-center justify-between rounded-2xl glass-accent px-4 py-3 text-sm text-cyan-200 hover:border-cyan-400/25 transition-all group"
          >
            <span className="inline-flex items-center gap-2">
              <ShieldCheck className="h-4 w-4" />
              Gerenciar equipes
            </span>
            <ArrowRight className="h-4 w-4 group-hover:translate-x-0.5 transition-transform" />
          </Link>
        </aside>
      </section>

      {/* Quick Links */}
      <section className="mt-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-4 animate-fade-up delay-400">
        {areas.map(({ href, title, icon: Icon }) => (
          <Link
            key={`quick-${href}`}
            href={href}
            className="group glass rounded-xl px-4 py-3 transition-all hover:border-cyan-400/15 hover:scale-[1.01]"
          >
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-cyan-400/8 border border-cyan-400/10 group-hover:bg-cyan-400/12 transition-colors">
                <Icon className="h-4 w-4 text-cyan-400" />
              </div>
              <div>
                <p className="text-sm font-medium text-white">{title}</p>
                <p className="text-xs text-gray-600">Entrar</p>
              </div>
            </div>
          </Link>
        ))}
      </section>
    </div>
  )
}
