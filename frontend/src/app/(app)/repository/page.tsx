'use client'

import Link from 'next/link'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ExternalLink, Repeat2 } from 'lucide-react'
import { ReleaseControlCenter } from '@/components/features/ReleaseControlCenter'
import { githubAPI } from '@/lib/api'
import { useAuthStore } from '@/store/auth'

export default function RepositoryPage() {
  const qc = useQueryClient()
  const { user } = useAuthStore()
  const githubLinked = Boolean(user?.github_id || user?.githubId)

  const reposQuery = useQuery({
    queryKey: ['github', 'repos'],
    queryFn: githubAPI.repos,
    enabled: githubLinked,
    staleTime: 60_000,
  })
  const profileQuery = useQuery({
    queryKey: ['github', 'profile'],
    queryFn: githubAPI.profile,
    enabled: githubLinked,
    staleTime: 60_000,
  })

  const syncReposMutation = useMutation({
    mutationFn: githubAPI.sync,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['github', 'repos'] })
    },
  })

  const githubRepos = reposQuery.data?.repos ?? []
  const githubProfile = profileQuery.data?.profile

  return (
    <div className="social-page">
      <section className="social-hero">
        <p className="text-xs font-mono uppercase tracking-[0.2em] text-cyan-300">Feed do Repositório</p>
        <h1 className="mt-2 text-3xl font-bold text-white">Timeline de releases</h1>
        <p className="mt-2 max-w-3xl text-sm text-gray-400">
          Navegue por versões, publique atualizações e acompanhe o estado do repositório como um feed de atividade.
        </p>
      </section>

      <section className="social-layout">
        <aside className="space-y-4">
          <div className="social-side-card">
            <p className="text-xs font-semibold uppercase tracking-widest text-gray-500">Comunidades ativas</p>
            <div className="mt-3 space-y-2">
              <div className="social-tile text-sm">Engenharia de Releases</div>
              <div className="social-tile text-sm">Revisão de Catálogo</div>
              <div className="social-tile text-sm">Time de Segurança</div>
            </div>
          </div>
          <div className="social-side-card">
            <p className="text-xs font-semibold uppercase tracking-widest text-gray-500">Atalhos</p>
            <div className="mt-3 space-y-2">
              <Link href="/dashboard" className="social-link">Voltar ao feed</Link>
              <Link href="/ops" className="social-link">Ver operações</Link>
            </div>
          </div>
        </aside>

        <main>
          <section className="glass rounded-2xl p-5 mb-4">
            <div className="flex items-center justify-between gap-3">
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-gray-500">GitHub</p>
                <h2 className="mt-1 text-base font-semibold text-white">Repositórios conectados</h2>
              </div>
              {githubLinked && (
                <button
                  onClick={() => syncReposMutation.mutate()}
                  disabled={syncReposMutation.isPending}
                  className="inline-flex items-center gap-2 rounded-xl bg-white/5 border border-white/10 px-3 py-1.5 text-sm text-gray-300 hover:bg-white/10 hover:text-white transition-all disabled:opacity-50"
                >
                  <Repeat2 className={`h-4 w-4 ${syncReposMutation.isPending ? 'animate-spin' : ''}`} />
                  Sincronizar
                </button>
              )}
            </div>

            {!githubLinked && (
              <p className="mt-3 text-sm text-gray-500">
                Faça login com GitHub para carregar seus repositórios nesta seção.
              </p>
            )}

            {githubLinked && reposQuery.isLoading && (
              <p className="mt-3 text-sm text-gray-500">Carregando repositórios do GitHub...</p>
            )}

            {githubProfile && (
              <div className="mt-3 rounded-xl border border-cyan-400/20 bg-cyan-400/5 p-3">
                <div className="flex items-center gap-3">
                  <img src={githubProfile.avatarUrl} alt={githubProfile.login} className="h-10 w-10 rounded-full border border-white/10 object-cover" />
                  <div className="min-w-0">
                    <p className="text-sm font-semibold text-white truncate">{githubProfile.name || githubProfile.login}</p>
                    <a href={githubProfile.htmlUrl} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs text-cyan-300 hover:text-cyan-200">
                      @{githubProfile.login} <ExternalLink className="h-3 w-3" />
                    </a>
                  </div>
                  <p className="ml-auto text-xs text-gray-400">{githubProfile.followers} seguidores · {githubProfile.publicRepos} repos</p>
                </div>
                {githubProfile.bio && <p className="mt-2 text-xs text-gray-400">{githubProfile.bio}</p>}
              </div>
            )}

            {githubLinked && !reposQuery.isLoading && githubRepos.length === 0 && (
              <p className="mt-3 text-sm text-gray-500">
                Nenhum repositório sincronizado ainda. Use o botão acima para buscar os dados.
              </p>
            )}

            {githubLinked && githubRepos.length > 0 && (
              <div className="mt-4 grid gap-3 sm:grid-cols-2">
                {githubRepos.slice(0, 8).map((repo) => (
                  <a
                    key={repo.id}
                    href={repo.htmlUrl}
                    target="_blank"
                    rel="noreferrer"
                    className="rounded-xl border border-white/10 bg-white/3 px-3 py-2.5 hover:bg-white/5 transition-all"
                  >
                    <p className="text-sm font-medium text-white truncate">{repo.fullName}</p>
                    <p className="mt-1 text-xs text-gray-500 line-clamp-2">{repo.description || 'Sem descrição.'}</p>
                    <p className="mt-2 text-[11px] text-gray-600">
                      {repo.language || 'N/A'} · ⭐ {repo.stargazers} · Forks {repo.forks}
                    </p>
                  </a>
                ))}
              </div>
            )}
          </section>

          <ReleaseControlCenter />
        </main>
      </section>
    </div>
  )
}
