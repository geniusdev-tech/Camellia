'use client'

import { useMemo, useState } from 'react'
import Link from 'next/link'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  AlertTriangle,
  ArrowRight,
  BookOpen,
  Building2,
  ExternalLink,
  GitCommitHorizontal,
  GitPullRequest,
  Globe2,
  Heart,
  Link2,
  MapPin,
  MessageSquare,
  RefreshCw,
  ShieldCheck,
  ShieldX,
  Star,
  Users,
} from 'lucide-react'
import { githubAPI } from '@/lib/api'
import type { GithubRepoScope, GithubRepoSort } from '@/lib/types'
import { useAuthStore } from '@/store/auth'

function MetricCard({ label, value, sub }: { label: string; value: string | number; sub?: string }) {
  return (
    <div className="glass rounded-2xl p-4">
      <p className="text-[10px] font-mono uppercase tracking-[0.2em] text-gray-500">{label}</p>
      <p className="mt-1 text-xl font-semibold text-white">{value}</p>
      {sub ? <p className="mt-1 text-xs text-gray-400">{sub}</p> : null}
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
  })

  const syncMutation = useMutation({
    mutationFn: githubAPI.sync,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['github', 'dashboard'] })
      qc.invalidateQueries({ queryKey: ['github', 'repos'] })
      qc.invalidateQueries({ queryKey: ['github', 'profile'] })
    },
  })

  const data = dashboardQuery.data
  const activityIcon = useMemo(() => ({
    commit: GitCommitHorizontal,
    pull_request: GitPullRequest,
    issue: MessageSquare,
  }), [])

  if (!githubLinked) {
    return (
      <div className="social-page">
        <section className="social-hero">
          <p className="text-xs font-mono uppercase tracking-[0.25em] text-cyan-300">GitHub Dashboard</p>
          <h1 className="mt-2 text-3xl sm:text-4xl font-bold text-white">Conecte sua conta GitHub</h1>
          <p className="mt-3 text-sm text-gray-300">Para ver perfil, atividade, saúde e segurança dos repositórios.</p>
          <Link href="/login" className="mt-4 inline-flex items-center gap-2 rounded-xl bg-cyan-400/20 border border-cyan-400/30 px-4 py-2 text-cyan-100">
            Ir para login <ArrowRight className="h-4 w-4" />
          </Link>
        </section>
      </div>
    )
  }

  return (
    <div className="social-page">
      <section className="glass rounded-3xl p-5 sm:p-7 mb-6 sm:mb-7 animate-fade-up">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="text-xs font-mono uppercase tracking-[0.25em] text-cyan-300">GitHub Dashboard</p>
            <h1 className="mt-2 text-3xl sm:text-4xl font-bold leading-tight text-white">Comunidade e Repositórios</h1>
            <p className="mt-3 max-w-3xl text-sm text-gray-300">
              Perfil, métricas, top repositórios, atividade recente, saúde e segurança com dados reais do GitHub.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => syncMutation.mutate()}
              disabled={syncMutation.isPending}
              className="h-btn-primary"
            >
              <RefreshCw className={`h-4 w-4 ${syncMutation.isPending ? 'animate-spin' : ''}`} />
              Sincronizar agora
            </button>
            <a href={data?.quickActions.githubProfileUrl} target="_blank" rel="noreferrer" className="h-btn">
              Abrir no GitHub <ExternalLink className="h-4 w-4" />
            </a>
          </div>
        </div>
      </section>

      {dashboardQuery.isLoading && <div className="text-sm text-gray-400">Carregando dados do GitHub...</div>}
      {dashboardQuery.isError && <div className="text-sm text-rose-300">Falha ao carregar dashboard GitHub.</div>}

      {data && (
        <>
          <section className="mb-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <MetricCard label="Repos Públicos" value={data.profile.publicRepos} sub={`cache: ${data.sync.cachedRepos}`} />
            <MetricCard label="Followers" value={data.profile.followers} sub={`Following: ${data.profile.following}`} />
            <MetricCard label="Último Sync" value={data.sync.lastSyncedAt ? new Date(data.sync.lastSyncedAt).toLocaleString('pt-BR') : 'N/A'} />
            <MetricCard label="Status Token" value={data.tokenStatus === 'ok' ? 'OK' : 'Expirado'} sub={data.tokenStatus === 'ok' ? 'Operacional' : 'Reautenticar'} />
          </section>

          <section className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
            <div className="space-y-6">
              <div className="glass rounded-2xl p-5">
                <div className="flex items-start gap-4">
                  <img src={data.profile.avatarUrl} alt={data.profile.login} className="h-14 w-14 rounded-full border border-white/10 object-cover" />
                  <div className="min-w-0">
                    <p className="text-lg font-semibold text-white truncate">{data.profile.name || data.profile.login}</p>
                    <a href={data.profile.htmlUrl} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-sm text-cyan-300 hover:text-cyan-200">
                      @{data.profile.login} <ExternalLink className="h-3 w-3" />
                    </a>
                    {data.profile.bio ? <p className="mt-2 text-sm text-gray-300">{data.profile.bio}</p> : null}
                    <div className="mt-2 flex flex-wrap gap-3 text-xs text-gray-400">
                      {data.profile.company ? <span className="inline-flex items-center gap-1"><Building2 className="h-3.5 w-3.5" />{data.profile.company}</span> : null}
                      {data.profile.location ? <span className="inline-flex items-center gap-1"><MapPin className="h-3.5 w-3.5" />{data.profile.location}</span> : null}
                      {data.profile.blog ? <a href={data.profile.blog} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-cyan-300"><Link2 className="h-3.5 w-3.5" />Website</a> : null}
                    </div>
                  </div>
                </div>
              </div>

              <div className="glass rounded-2xl p-5">
                <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                  <h2 className="text-lg font-semibold text-white">Top Repositórios</h2>
                  <div className="flex flex-wrap gap-2">
                    <select className="h-input !py-2 !px-3 !w-auto text-sm" value={scope} onChange={(e) => setScope(e.target.value as GithubRepoScope)}>
                      <option value="all">todos</option>
                      <option value="owner">só owner</option>
                      <option value="org">só org</option>
                    </select>
                    <select className="h-input !py-2 !px-3 !w-auto text-sm" value={sortBy} onChange={(e) => setSortBy(e.target.value as GithubRepoSort)}>
                      <option value="updated">mais atualizados</option>
                      <option value="stars">mais stars</option>
                      <option value="forks">mais forks</option>
                    </select>
                  </div>
                </div>
                <div className="space-y-2.5">
                  {data.topRepositories.map((repo) => (
                    <a key={repo.id} href={repo.htmlUrl} target="_blank" rel="noreferrer" className="block rounded-xl border border-white/10 bg-white/3 p-3 hover:border-cyan-400/30 hover:bg-white/5 transition-all">
                      <div className="flex items-center justify-between gap-3">
                        <p className="text-sm font-semibold text-white truncate">{repo.fullName}</p>
                        <span className="text-[11px] text-gray-500">{new Date(repo.updatedAt).toLocaleDateString('pt-BR')}</span>
                      </div>
                      <p className="mt-1 text-xs text-gray-400 line-clamp-2">{repo.description || 'Sem descrição.'}</p>
                      <div className="mt-2 flex flex-wrap gap-3 text-xs text-gray-500">
                        <span className="inline-flex items-center gap-1"><Star className="h-3.5 w-3.5" />{repo.stargazers}</span>
                        <span>{repo.forks} forks</span>
                        <span>{repo.openIssues} issues</span>
                        <span>{repo.language || 'N/A'}</span>
                        <span>{repo.ownerType}</span>
                      </div>
                    </a>
                  ))}
                </div>
              </div>

              <div className="glass rounded-2xl p-5">
                <h2 className="text-lg font-semibold text-white">Atividade recente (7 dias)</h2>
                <div className="mt-3 space-y-2.5">
                  {data.recentActivity.length === 0 ? <p className="text-sm text-gray-500">Sem atividade recente visível.</p> : null}
                  {data.recentActivity.map((item, idx) => {
                    const Icon = activityIcon[item.type]
                    return (
                      <a key={`${item.repo}-${item.createdAt}-${idx}`} href={item.url} target="_blank" rel="noreferrer" className="flex items-start gap-3 rounded-xl border border-white/10 bg-white/3 px-3 py-2.5 hover:bg-white/5">
                        <Icon className="h-4 w-4 mt-0.5 text-cyan-300" />
                        <div className="min-w-0">
                          <p className="text-sm text-white truncate">{item.title}</p>
                          <p className="text-xs text-gray-500">{item.repo} · {new Date(item.createdAt).toLocaleString('pt-BR')}</p>
                        </div>
                      </a>
                    )
                  })}
                </div>
              </div>
            </div>

            <aside className="space-y-6">
              <div className="glass rounded-2xl p-5">
                <div className="flex items-center justify-between gap-2">
                  <h2 className="text-base font-semibold text-white">Saúde dos Repositórios</h2>
                  <select
                    className="h-input !py-1.5 !px-2.5 !w-auto text-xs"
                    value={issuesThreshold}
                    onChange={(e) => setIssuesThreshold(Number(e.target.value))}
                  >
                    <option value={5}>issues &gt; 5</option>
                    <option value={10}>issues &gt; 10</option>
                    <option value={20}>issues &gt; 20</option>
                    <option value={50}>issues &gt; 50</option>
                  </select>
                </div>
                <div className="mt-3 space-y-2 text-sm text-gray-300">
                  <div className="flex justify-between"><span>Sem descrição</span><span>{data.health.reposWithoutDescription}</span></div>
                  <div className="flex justify-between"><span>Sem licença</span><span>{data.health.reposWithoutLicense}</span></div>
                  <div className="flex justify-between"><span>Issues &gt; {data.health.issuesThreshold}</span><span>{data.health.reposWithOpenIssuesAboveThreshold}</span></div>
                </div>
                <div className="mt-4">
                  <p className="text-xs font-mono uppercase tracking-[0.2em] text-gray-500 mb-2">Linguagens</p>
                  <div className="space-y-1.5">
                    {data.health.languages.map((lang) => (
                      <div key={lang.language} className="flex items-center justify-between text-xs text-gray-400">
                        <span>{lang.language}</span>
                        <span>{lang.count}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              <div className="glass rounded-2xl p-5">
                <h2 className="text-base font-semibold text-white">Segurança básica</h2>
                <div className="mt-3 space-y-2 text-sm text-gray-300">
                  <div className="flex items-center justify-between"><span>Branch protection</span><span>{data.security.withBranchProtection}/{data.security.scannedRepos}</span></div>
                  <div className="flex items-center justify-between"><span>Sem proteção</span><span>{data.security.withoutBranchProtection}</span></div>
                  <div className="flex items-center justify-between"><span>Dependabot</span><span>{data.security.dependabotAvailable ? String(data.security.reposWithDependabotAlerts ?? 0) : 'N/A'}</span></div>
                  <div className="flex items-center justify-between"><span>Code scanning</span><span>{data.security.codeScanningAvailable ? String(data.security.reposWithCodeScanningAlerts ?? 0) : 'N/A'}</span></div>
                </div>
              </div>

              <div className="glass rounded-2xl p-5">
                <h2 className="text-base font-semibold text-white">Ações rápidas</h2>
                <div className="mt-3 grid gap-2">
                  <a href={data.quickActions.githubProfileUrl} target="_blank" rel="noreferrer" className="h-btn justify-between">Abrir no GitHub <ExternalLink className="h-4 w-4" /></a>
                  <button onClick={() => syncMutation.mutate()} className="h-btn justify-between">Sincronizar agora <RefreshCw className="h-4 w-4" /></button>
                  <a href={data.quickActions.openPullRequestsUrl} target="_blank" rel="noreferrer" className="h-btn justify-between">Ir para PRs abertas <GitPullRequest className="h-4 w-4" /></a>
                  {data.quickActions.createIssueUrl ? (
                    <a href={data.quickActions.createIssueUrl} target="_blank" rel="noreferrer" className="h-btn justify-between">Criar issue <BookOpen className="h-4 w-4" /></a>
                  ) : (
                    <span className="h-btn justify-between opacity-60 cursor-not-allowed">Criar issue <AlertTriangle className="h-4 w-4" /></span>
                  )}
                </div>
              </div>

              <Link href="/repository" className="flex items-center justify-between rounded-2xl glass-accent px-4 py-3 text-sm text-cyan-200 hover:border-cyan-400/25 transition-all group">
                <span className="inline-flex items-center gap-2">
                  <Globe2 className="h-4 w-4" />
                  Ver Repositório Completo
                </span>
                <ArrowRight className="h-4 w-4 group-hover:translate-x-0.5 transition-transform" />
              </Link>
            </aside>
          </section>
        </>
      )}
    </div>
  )
}
