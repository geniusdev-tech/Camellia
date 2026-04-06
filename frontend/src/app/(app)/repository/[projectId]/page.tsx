'use client'

import Link from 'next/link'
import { useMemo } from 'react'
import { useParams } from 'next/navigation'
import { useQuery } from '@tanstack/react-query'
import { ExternalLink, FolderGit2, Star } from 'lucide-react'
import { githubAPI } from '@/lib/api'
import { useAuthStore } from '@/store/auth'

export default function RepositoryDetailPage() {
  const params = useParams<{ projectId: string }>()
  const projectId = params?.projectId || ''
  const { user } = useAuthStore()
  const githubLinked = Boolean(user?.github_id || user?.githubId)

  const reposQuery = useQuery({
    queryKey: ['github', 'repos', 'detail', projectId],
    queryFn: githubAPI.repos,
    enabled: githubLinked,
    staleTime: 60_000,
    retry: 1,
  })

  const repos = reposQuery.data?.repos ?? []
  const repository = useMemo(
    () => repos.find((repo) => repo.id === projectId || String(repo.githubId) === projectId || repo.name === projectId || repo.fullName === projectId),
    [repos, projectId],
  )

  if (!githubLinked) {
    return (
      <div className="social-page">
        <section className="social-hero">
          <h1 className="text-3xl font-bold text-slate-100">Detalhe de repositório</h1>
          <p className="mt-2 text-sm text-slate-300">Conecte seu GitHub para visualizar os dados.</p>
          <Link href="/login" className="mt-4 inline-flex rounded-xl border border-orange-400/35 bg-orange-500/15 px-4 py-2 text-sm text-orange-100">Ir para login</Link>
        </section>
      </div>
    )
  }

  return (
    <div className="social-page space-y-4">
      <section className="social-hero">
        <div className="social-hero-content">
          <div className="hero-badge">Repository detail</div>
          <h1 className="mt-3 text-3xl font-semibold text-white">{repository?.fullName || projectId}</h1>
          <p className="mt-2 text-sm text-slate-300">Visão individual alimentada pelo cache GitHub.</p>
        </div>
        <div className="social-hero-cta">
          <p className="text-xs text-slate-400">Identificador: nome/fullName ou GitHub ID.</p>
        </div>
      </section>

      {reposQuery.isLoading && <p className="text-sm text-slate-400">Carregando repositório...</p>}
      {reposQuery.isError && <p className="rounded-xl border border-amber-400/30 bg-amber-400/10 px-3 py-2 text-sm text-amber-200">Não foi possível carregar dados do GitHub.</p>}

      {repository ? (
        <section className="social-side-card">
          <div className="flex items-start justify-between gap-3">
            <div>
              <div className="inline-flex items-center gap-2 text-orange-300"><FolderGit2 className="h-4 w-4" /> {repository.fullName}</div>
              <p className="mt-2 text-sm text-slate-300">{repository.description || 'Sem descrição.'}</p>
              <p className="mt-2 text-xs text-slate-400">Atualizado em {new Date(repository.dbUpdatedAt).toLocaleString('pt-BR')}</p>
            </div>
            <a href={repository.htmlUrl} target="_blank" rel="noreferrer" className="h-btn inline-flex">
              Abrir no GitHub <ExternalLink className="h-4 w-4" />
            </a>
          </div>

          <div className="mt-4 grid gap-2 sm:grid-cols-3">
            <div className="social-tile"><p className="text-[11px] text-slate-400">Linguagem</p><p className="mt-1 text-sm font-semibold text-slate-100">{repository.language || 'N/A'}</p></div>
            <div className="social-tile"><p className="text-[11px] text-slate-400">Stars</p><p className="mt-1 inline-flex items-center gap-1 text-sm font-semibold text-slate-100"><Star className="h-3 w-3" />{repository.stargazers}</p></div>
            <div className="social-tile"><p className="text-[11px] text-slate-400">Forks</p><p className="mt-1 text-sm font-semibold text-slate-100">{repository.forks}</p></div>
          </div>
        </section>
      ) : (
        <section className="social-side-card">
          <p className="text-sm text-slate-300">O identificador <span className="font-mono text-slate-100">{projectId}</span> não corresponde a um repositório no cache atual.</p>
          <Link href="/repository" className="mt-3 inline-flex h-btn">Voltar para lista</Link>
        </section>
      )}
    </div>
  )
}
