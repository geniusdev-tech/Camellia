'use client'

import Link from 'next/link'
import { useQuery } from '@tanstack/react-query'
import { ExternalLink, Star } from 'lucide-react'
import { githubAPI } from '@/lib/api'
import { useAuthStore } from '@/store/auth'

export default function CatalogPage() {
  const { user } = useAuthStore()
  const githubLinked = Boolean(user?.github_id || user?.githubId)

  const dashboardQuery = useQuery({
    queryKey: ['github', 'dashboard', 'catalog-view'],
    queryFn: () => githubAPI.dashboard({ scope: 'all', sortBy: 'stars', issuesThreshold: 10 }),
    enabled: githubLinked,
    staleTime: 45_000,
    retry: 1,
  })

  const data = dashboardQuery.data

  if (!githubLinked) {
    return (
      <div className="social-page">
        <section className="social-hero">
          <h1 className="text-3xl font-bold text-slate-100">Catálogo GitHub</h1>
          <p className="mt-2 text-sm text-slate-300">Conecte o GitHub para listar os repositórios com maior destaque.</p>
          <Link href="/login" className="mt-4 inline-flex rounded-xl border border-orange-400/35 bg-orange-500/15 px-4 py-2 text-sm text-orange-100">Ir para login</Link>
        </section>
      </div>
    )
  }

  return (
    <div className="social-page space-y-4">
      <section className="social-hero">
        <div className="social-hero-content">
          <div className="hero-badge">Catalog</div>
          <h1 className="mt-3 text-3xl font-semibold text-white">Repositórios em destaque</h1>
          <p className="mt-2 text-sm text-slate-300">Ranking por estrelas direto do GitHub.</p>
        </div>
        <div className="social-hero-cta">
          <p className="text-xs text-slate-400">Atualizações automáticas via sync.</p>
        </div>
      </section>

      {dashboardQuery.isLoading && <p className="text-sm text-slate-400">Carregando catálogo...</p>}
      {dashboardQuery.isError && <p className="rounded-xl border border-amber-400/30 bg-amber-400/10 px-3 py-2 text-sm text-amber-200">Falha ao carregar o catálogo.</p>}

      {data && (
        <>
          <section className="social-side-card">
            <p className="text-xs font-mono uppercase tracking-[0.18em] text-slate-400">Linguagens mais usadas</p>
            <div className="mt-3 grid gap-2 sm:grid-cols-2">
              {data.health.languages.map((lang) => (
                <div key={lang.language} className="social-tile flex items-center justify-between">
                  <span className="text-sm text-slate-100">{lang.language}</span>
                  <span className="text-xs text-slate-400">{lang.count}</span>
                </div>
              ))}
            </div>
          </section>

          <section className="social-side-card">
            <p className="text-xs font-mono uppercase tracking-[0.18em] text-slate-400">Top repositórios por estrela</p>
            <div className="mt-3 space-y-2">
              {data.topRepositories.map((repo) => (
                <a key={repo.id} href={repo.htmlUrl} target="_blank" rel="noreferrer" className="social-tile block hover:border-orange-400/35">
                  <div className="flex items-center justify-between gap-2">
                    <p className="truncate text-sm font-semibold text-slate-100">{repo.fullName}</p>
                    <ExternalLink className="h-4 w-4 text-orange-300" />
                  </div>
                  <p className="mt-1 line-clamp-2 text-xs text-slate-400">{repo.description || 'Sem descrição.'}</p>
                  <div className="mt-2 flex items-center gap-3 text-xs text-slate-400">
                    <span className="inline-flex items-center gap-1"><Star className="h-3 w-3" />{repo.stargazers}</span>
                    <span>{repo.language || 'N/A'}</span>
                    <span>{new Date(repo.updatedAt).toLocaleDateString('pt-BR')}</span>
                  </div>
                </a>
              ))}
            </div>
          </section>
        </>
      )}
    </div>
  )
}
