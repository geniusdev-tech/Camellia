'use client'

import Link from 'next/link'
import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  ArrowRight,
  BookOpen,
  ExternalLink,
  GitCommitHorizontal,
  GitPullRequest,
  Globe2,
  MessageSquare,
  RefreshCw,
  Star,
} from 'lucide-react'
import { githubAPI } from '@/lib/api'
import type { GithubRepoScope, GithubRepoSort } from '@/lib/types'
import { useAuthStore } from '@/store/auth'

function Metric({ label, value, helper }: { label: string; value: string | number; helper?: string }) {
  return (
    <div className="social-tile">
      <p className="text-[11px] uppercase tracking-[0.16em] text-slate-400">{label}</p>
      <p className="mt-1 text-xl font-semibold text-slate-100">{value}</p>
      {helper ? <p className="mt-1 text-xs text-slate-500">{helper}</p> : null}
    </div>
  )
}

export default function DashboardPage() {
  const qc = useQueryClient()
  const { user } = useAuthStore()
  const githubLinked = Boolean(user?.github_id || user?.githubId)
  const [scope, setScope] = useState<GithubRepoScope>('all')
  const [sortBy, setSortBy] = useState<GithubRepoSort>('updated')
  const [issuesThreshold, setIssuesThreshold] = useState(10)

  const dashboardQuery = useQuery({
    queryKey: ['github', 'dashboard', scope, sortBy, issuesThreshold],
    queryFn: () => githubAPI.dashboard({ scope, sortBy, issuesThreshold }),
    enabled: githubLinked,
    staleTime: 45_000,
    retry: 1,
  })
  const profileQuery = useQuery({
    queryKey: ['github', 'profile', 'dashboard-fallback'],
    queryFn: githubAPI.profile,
    enabled: githubLinked,
    staleTime: 60_000,
  })
  const reposQuery = useQuery({
    queryKey: ['github', 'repos', 'dashboard-fallback'],
    queryFn: githubAPI.repos,
    enabled: githubLinked,
    staleTime: 60_000,
  })
  const syncMutation = useMutation({
    mutationFn: githubAPI.sync,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['github'] }),
  })

  const data = dashboardQuery.data
  const profile = data?.profile ?? profileQuery.data?.profile
  const repos = reposQuery.data?.repos ?? []
  const topRepositories = data?.topRepositories ?? repos.map((repo) => ({
    id: repo.githubId,
    name: repo.name,
    fullName: repo.fullName,
    description: repo.description,
    htmlUrl: repo.htmlUrl,
    language: repo.language,
    stargazers: repo.stargazers,
    forks: repo.forks,
    updatedAt: repo.dbUpdatedAt,
    openIssues: 0,
    ownerLogin: profile?.login || '',
    ownerType: 'User',
  }))
  const activityIcon = useMemo(() => ({
    commit: GitCommitHorizontal,
    pull_request: GitPullRequest,
    issue: MessageSquare,
  }), [])

  if (!githubLinked) {
    return (
      <div className="social-page">
        <section className="social-hero">
          <p className="text-xs font-mono uppercase tracking-[0.22em] text-orange-300">GitHub Dashboard</p>
          <h1 className="mt-2 text-3xl font-bold text-slate-100">Conecte sua conta GitHub</h1>
          <p className="mt-2 text-sm text-slate-300">Somente dados do GitHub são exibidos no dashboard.</p>
          <Link href="/login" className="mt-4 inline-flex items-center gap-2 rounded-xl border border-orange-400/35 bg-orange-500/15 px-4 py-2 text-sm text-orange-100">
            Ir para login <ArrowRight className="h-4 w-4" />
          </Link>
        </section>
      </div>
    )
  }

  return (
    <div className="social-page space-y-4">
      <section className="social-hero">
        <div className="social-hero-content">
          <div className="hero-badge">GitHub Dashboard</div>
          <h1 className="mt-3 text-3xl font-semibold text-white">Resumo de perfil, repositórios e saúde</h1>
          <p className="mt-2 text-sm text-slate-300">Dados sincronizados do GitHub com foco em comunidade e segurança.</p>
        </div>
        <div className="social-hero-cta">
          <button onClick={() => syncMutation.mutate()} disabled={syncMutation.isPending} className="h-btn-primary">
            <RefreshCw className={`h-4 w-4 ${syncMutation.isPending ? 'animate-spin' : ''}`} />
            Sincronizar
          </button>
          <a href={data?.quickActions.githubProfileUrl || profile?.htmlUrl || '#'} target="_blank" rel="noreferrer" className="h-btn">
            Abrir GitHub <ExternalLink className="h-4 w-4" />
          </a>
        </div>
      </section>

      {dashboardQuery.isLoading ? <p className="text-sm text-slate-400">Carregando dados...</p> : null}
      {dashboardQuery.isError ? <p className="rounded-xl border border-amber-400/30 bg-amber-400/10 px-3 py-2 text-sm text-amber-200">Falha no dashboard avançado. Exibindo dados básicos.</p> : null}

      {(data || profile || repos.length > 0) ? (
        <>
          <section className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
            <Metric label="Repos Públicos" value={profile?.publicRepos ?? repos.length} helper={`cache: ${data?.sync.cachedRepos ?? repos.length}`} />
            <Metric label="Followers" value={profile?.followers ?? 'N/A'} helper={`Following: ${profile?.following ?? 'N/A'}`} />
            <Metric label="Último Sync" value={data?.sync.lastSyncedAt ? new Date(data.sync.lastSyncedAt).toLocaleString('pt-BR') : 'N/A'} />
            <Metric label="Token" value={data?.tokenStatus === 'expired' ? 'Expirado' : 'OK'} />
          </section>

          <section className="grid gap-3 xl:grid-cols-[1.2fr_0.8fr]">
            <div className="space-y-3">
              <div className="social-side-card">
                <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                  <h2 className="text-sm font-semibold text-slate-100">Top Repositórios</h2>
                  <div className="flex gap-2">
                    <select className="h-input !w-auto !px-2.5 !py-1.5 text-xs" value={scope} onChange={(e) => setScope(e.target.value as GithubRepoScope)}>
                      <option value="all">todos</option>
                      <option value="owner">owner</option>
                      <option value="org">org</option>
                    </select>
                    <select className="h-input !w-auto !px-2.5 !py-1.5 text-xs" value={sortBy} onChange={(e) => setSortBy(e.target.value as GithubRepoSort)}>
                      <option value="updated">atualizados</option>
                      <option value="stars">stars</option>
                      <option value="forks">forks</option>
                    </select>
                  </div>
                </div>
                <div className="space-y-2">
                  {topRepositories.map((repo) => (
                    <a key={repo.id} href={repo.htmlUrl} target="_blank" rel="noreferrer" className="social-tile block hover:border-orange-400/35">
                      <div className="flex items-center justify-between gap-2">
                        <p className="truncate text-sm font-semibold text-slate-100">{repo.fullName}</p>
                        <span className="text-[11px] text-slate-500">{new Date(repo.updatedAt).toLocaleDateString('pt-BR')}</span>
                      </div>
                      <p className="mt-1 line-clamp-2 text-xs text-slate-400">{repo.description || 'Sem descrição.'}</p>
                      <div className="mt-2 flex flex-wrap gap-3 text-xs text-slate-400">
                        <span className="inline-flex items-center gap-1"><Star className="h-3 w-3" />{repo.stargazers}</span>
                        <span>{repo.forks} forks</span>
                        <span>{repo.openIssues} issues</span>
                        <span>{repo.language || 'N/A'}</span>
                      </div>
                    </a>
                  ))}
                </div>
              </div>

              {data ? (
                <div className="social-side-card">
                  <h2 className="text-sm font-semibold text-slate-100">Atividade Recente</h2>
                  <div className="mt-3 space-y-2">
                    {data.recentActivity.length === 0 ? <p className="text-sm text-slate-500">Sem atividade recente.</p> : null}
                    {data.recentActivity.map((item, idx) => {
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
                </div>
              ) : null}
            </div>

            <aside className="space-y-3">
              {data ? (
                <div className="social-side-card">
                  <div className="mb-3 flex items-center justify-between">
                    <h2 className="text-sm font-semibold text-slate-100">Saúde</h2>
                    <select className="h-input !w-auto !px-2.5 !py-1.5 text-xs" value={issuesThreshold} onChange={(e) => setIssuesThreshold(Number(e.target.value))}>
                      <option value={5}>issues &gt; 5</option>
                      <option value={10}>issues &gt; 10</option>
                      <option value={20}>issues &gt; 20</option>
                      <option value={50}>issues &gt; 50</option>
                    </select>
                  </div>
                  <div className="space-y-2 text-sm text-slate-300">
                    <div className="flex justify-between"><span>Sem descrição</span><span>{data.health.reposWithoutDescription}</span></div>
                    <div className="flex justify-between"><span>Sem licença</span><span>{data.health.reposWithoutLicense}</span></div>
                    <div className="flex justify-between"><span>Issues &gt; {data.health.issuesThreshold}</span><span>{data.health.reposWithOpenIssuesAboveThreshold}</span></div>
                  </div>
                  <div className="mt-3 space-y-1.5">
                    {data.health.languages.map((lang) => (
                      <div key={lang.language} className="social-tile flex items-center justify-between py-2">
                        <span className="text-xs text-slate-300">{lang.language}</span>
                        <span className="text-xs text-slate-500">{lang.count}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : null}

              {data ? (
                <div className="social-side-card">
                  <h2 className="text-sm font-semibold text-slate-100">Ações</h2>
                  <div className="mt-3 grid gap-2">
                    <a href={data.quickActions.openPullRequestsUrl} target="_blank" rel="noreferrer" className="h-btn justify-between">PRs abertas <GitPullRequest className="h-4 w-4" /></a>
                    {data.quickActions.createIssueUrl ? (
                      <a href={data.quickActions.createIssueUrl} target="_blank" rel="noreferrer" className="h-btn justify-between">Criar issue <BookOpen className="h-4 w-4" /></a>
                    ) : (
                      <span className="h-btn justify-between opacity-60">Criar issue <BookOpen className="h-4 w-4" /></span>
                    )}
                  </div>
                </div>
              ) : null}

              <Link href="/repository" className="h-btn-primary flex w-full items-center justify-between">
                <span className="inline-flex items-center gap-2"><Globe2 className="h-4 w-4" />Abrir Repositórios</span>
                <ArrowRight className="h-4 w-4" />
              </Link>
            </aside>
          </section>
        </>
      ) : null}
    </div>
  )
}
