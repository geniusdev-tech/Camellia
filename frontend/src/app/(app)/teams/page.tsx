'use client'

import Link from 'next/link'
import { useQuery } from '@tanstack/react-query'
import { ExternalLink, Users } from 'lucide-react'
import { githubAPI } from '@/lib/api'
import { useAuthStore } from '@/store/auth'

export default function TeamsPage() {
  const { user } = useAuthStore()
  const githubLinked = Boolean(user?.github_id || user?.githubId)

  const reposQuery = useQuery({
    queryKey: ['github', 'repos', 'teams-view'],
    queryFn: githubAPI.repos,
    enabled: githubLinked,
    staleTime: 60_000,
    retry: 1,
  })

  const dashboardQuery = useQuery({
    queryKey: ['github', 'dashboard', 'teams-view'],
    queryFn: () => githubAPI.dashboard({ sortBy: 'updated', scope: 'all', issuesThreshold: 10 }),
    enabled: githubLinked,
    staleTime: 45_000,
    retry: 1,
  })

  const repos = reposQuery.data?.repos ?? []
  const organizations = repos.reduce<Record<string, number>>((acc, repo) => {
    const owner = repo.fullName.split('/')[0] || 'unknown'
    acc[owner] = (acc[owner] || 0) + 1
    return acc
  }, {})
  const orgList = Object.entries(organizations).sort((a, b) => b[1] - a[1])

  if (!githubLinked) {
    return (
      <div className="social-page">
        <section className="social-hero">
          <h1 className="text-3xl font-bold text-slate-100">Times via GitHub</h1>
          <p className="mt-2 text-sm text-slate-300">Conecte o GitHub para listar organizações e owners dos seus repositórios.</p>
          <Link href="/login" className="mt-4 inline-flex rounded-xl border border-orange-400/35 bg-orange-500/15 px-4 py-2 text-sm text-orange-100">Ir para login</Link>
        </section>
      </div>
    )
  }

  return (
    <div className="social-page space-y-4">
      <section className="social-hero">
        <div className="social-hero-content">
          <div className="hero-badge">Teams</div>
          <h1 className="mt-3 text-3xl font-semibold text-white">Owners e organizações</h1>
          <p className="mt-2 text-sm text-slate-300">Agrupamento dos repositórios por owner para visão de colaboração.</p>
        </div>
        <div className="social-hero-cta">
          <p className="text-xs text-slate-400">Ganhe contexto imediato sobre times GitHub.</p>
        </div>
      </section>

      <section className="social-side-card">
        <p className="text-xs font-mono uppercase tracking-[0.18em] text-slate-400">Organizações detectadas</p>
        <div className="mt-3 grid gap-2 sm:grid-cols-2">
          {orgList.length === 0 && !reposQuery.isLoading ? <p className="text-sm text-slate-400">Sem dados de owners.</p> : null}
          {orgList.map(([org, count]) => (
            <div key={org} className="social-tile">
              <p className="text-sm font-semibold text-slate-100">{org}</p>
              <p className="mt-1 text-xs text-slate-400">{count} repositório(s)</p>
            </div>
          ))}
        </div>
      </section>

      <section className="social-side-card">
        <p className="text-xs font-mono uppercase tracking-[0.18em] text-slate-400">Top repositórios por atividade</p>
        <div className="mt-3 space-y-2">
          {(dashboardQuery.data?.topRepositories ?? []).slice(0, 8).map((repo) => (
            <a key={repo.id} href={repo.htmlUrl} target="_blank" rel="noreferrer" className="social-tile flex items-center justify-between gap-2">
              <div className="min-w-0">
                <p className="truncate text-sm font-semibold text-slate-100">{repo.fullName}</p>
                <p className="text-xs text-slate-500">{repo.ownerType} • {repo.language || 'N/A'}</p>
              </div>
              <ExternalLink className="h-4 w-4 text-orange-300" />
            </a>
          ))}
        </div>
      </section>

      <div className="social-side-card inline-flex items-center gap-2 text-sm text-slate-300">
        <Users className="h-4 w-4 text-orange-300" />
        Total de repositórios mapeados: <strong className="text-slate-100">{repos.length}</strong>
      </div>
    </div>
  )
}
