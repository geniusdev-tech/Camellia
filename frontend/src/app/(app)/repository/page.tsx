'use client'

import Link from 'next/link'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ExternalLink, GitCommitHorizontal, GitPullRequest, MessageSquare, RefreshCw, Star } from 'lucide-react'
import { githubAPI } from '@/lib/api'
import { useAuthStore } from '@/store/auth'

export default function RepositoryPage() {
  const qc = useQueryClient()
  const { user } = useAuthStore()
  const githubLinked = Boolean(user?.github_id || user?.githubId)

  const dashboardQuery = useQuery({
    queryKey: ['github', 'dashboard', 'repository-feed'],
    queryFn: () => githubAPI.dashboard({ sortBy: 'updated', scope: 'all', issuesThreshold: 10 }),
    enabled: githubLinked,
    staleTime: 45_000,
    retry: 1,
  })

  const reposQuery = useQuery({
    queryKey: ['github', 'repos'],
    queryFn: githubAPI.repos,
    enabled: githubLinked,
    staleTime: 60_000,
    retry: 1,
  })

  const profileQuery = useQuery({
    queryKey: ['github', 'profile'],
    queryFn: githubAPI.profile,
    enabled: githubLinked,
    staleTime: 60_000,
    retry: 1,
  })

  const syncMutation = useMutation({
    mutationFn: githubAPI.sync,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['github'] })
    },
  })

  const repos = reposQuery.data?.repos ?? []
  const profile = profileQuery.data?.profile
  const activity = dashboardQuery.data?.recentActivity ?? []

  const activityIcon = {
    commit: GitCommitHorizontal,
    pull_request: GitPullRequest,
    issue: MessageSquare,
  } as const

  if (!githubLinked) {
    return (
      <div className="social-page">
        <section className="social-hero">
          <p className="text-xs font-mono uppercase tracking-[0.22em] text-orange-300">Repository Feed</p>
          <h1 className="mt-2 text-3xl font-bold text-slate-100">Conecte sua conta GitHub</h1>
          <p className="mt-2 text-sm text-slate-300">Esta rota mostra apenas dados sincronizados do GitHub.</p>
          <Link href="/login" className="mt-4 inline-flex items-center gap-2 rounded-xl border border-orange-400/35 bg-orange-500/15 px-4 py-2 text-sm text-orange-100">
            Ir para login
          </Link>
        </section>
      </div>
    )
  }

  return (
    <div className="social-page space-y-4">
      <section className="social-hero">
        <div className="social-hero-content">
          <div className="hero-badge">Repository feed</div>
          <h1 className="mt-3 text-3xl font-semibold text-white">Repositórios e atividade recente</h1>
          <p className="mt-2 text-sm text-slate-300">Feed social com dados oficiais do GitHub.</p>
        </div>
        <div className="social-hero-cta">
          <button onClick={() => syncMutation.mutate()} disabled={syncMutation.isPending} className="h-btn-primary">
            <RefreshCw className={`h-4 w-4 ${syncMutation.isPending ? 'animate-spin' : ''}`} />
            Sincronizar
          </button>
        </div>
      </section>

      {reposQuery.isLoading && <p className="text-sm text-slate-400">Carregando repositórios...</p>}
      {reposQuery.isError && <p className="rounded-xl border border-amber-400/30 bg-amber-400/10 px-3 py-2 text-sm text-amber-200">Falha ao carregar repositórios.</p>}

      <section className="grid gap-3 lg:grid-cols-2">
        <div className="social-side-card">
          <p className="text-xs font-mono uppercase tracking-[0.18em] text-slate-400">Perfil GitHub</p>
          {profile ? (
            <div className="mt-3 flex items-start gap-3">
              <img src={profile.avatarUrl} alt={profile.login} className="h-12 w-12 rounded-full border border-slate-600/70 object-cover" />
              <div className="min-w-0">
                <p className="truncate text-sm font-semibold text-slate-100">{profile.name || profile.login}</p>
                <a href={profile.htmlUrl} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs text-orange-300 hover:text-orange-200">
                  @{profile.login} <ExternalLink className="h-3 w-3" />
                </a>
                <p className="mt-1 text-xs text-slate-400">{profile.followers} seguidores • {profile.following} seguindo • {profile.publicRepos} repositórios</p>
              </div>
            </div>
          ) : (
            <p className="mt-3 text-sm text-slate-400">Perfil indisponível.</p>
          )}
        </div>

        <div className="social-side-card">
          <p className="text-xs font-mono uppercase tracking-[0.18em] text-slate-400">Resumo</p>
          <div className="mt-3 grid grid-cols-2 gap-2">
            <div className="social-tile">
              <p className="text-[11px] text-slate-400">Repos em cache</p>
              <p className="mt-1 text-lg font-semibold text-slate-100">{repos.length}</p>
            </div>
            <div className="social-tile">
              <p className="text-[11px] text-slate-400">Último sync</p>
              <p className="mt-1 text-sm font-semibold text-slate-100">{dashboardQuery.data?.sync.lastSyncedAt ? new Date(dashboardQuery.data.sync.lastSyncedAt).toLocaleDateString('pt-BR') : 'N/A'}</p>
            </div>
          </div>
        </div>
      </section>

      <section className="social-side-card">
        <p className="text-xs font-mono uppercase tracking-[0.18em] text-slate-400">Repositórios</p>
        <div className="mt-3 space-y-2">
          {repos.length === 0 && !reposQuery.isLoading ? <p className="text-sm text-slate-400">Nenhum repositório sincronizado.</p> : null}
          {repos.map((repo) => (
            <a key={repo.id} href={repo.htmlUrl} target="_blank" rel="noreferrer" className="social-tile block hover:border-orange-400/35">
              <div className="flex items-center justify-between gap-2">
                <p className="truncate text-sm font-semibold text-slate-100">{repo.fullName}</p>
                <span className="text-[11px] text-slate-500">{new Date(repo.dbUpdatedAt).toLocaleDateString('pt-BR')}</span>
              </div>
              <p className="mt-1 line-clamp-2 text-xs text-slate-400">{repo.description || 'Sem descrição.'}</p>
              <div className="mt-2 flex items-center gap-3 text-xs text-slate-400">
                <span className="inline-flex items-center gap-1"><Star className="h-3 w-3" />{repo.stargazers}</span>
                <span>Forks {repo.forks}</span>
                <span>{repo.language || 'N/A'}</span>
              </div>
            </a>
          ))}
        </div>
      </section>

      <section className="social-side-card">
        <p className="text-xs font-mono uppercase tracking-[0.18em] text-slate-400">Atividade recente</p>
        <div className="mt-3 space-y-2">
          {activity.length === 0 ? <p className="text-sm text-slate-400">Sem eventos recentes.</p> : null}
          {activity.map((item, idx) => {
            const Icon = activityIcon[item.type]
            return (
              <a key={`${item.repo}-${item.createdAt}-${idx}`} href={item.url} target="_blank" rel="noreferrer" className="social-tile flex items-start gap-2.5">
                <Icon className="mt-0.5 h-4 w-4 text-orange-300" />
                <div className="min-w-0">
                  <p className="truncate text-sm text-slate-100">{item.title}</p>
                  <p className="text-xs text-slate-500">{item.repo} • {new Date(item.createdAt).toLocaleString('pt-BR')}</p>
                </div>
              </a>
            )
          })}
        </div>
      </section>
    </div>
  )
}
