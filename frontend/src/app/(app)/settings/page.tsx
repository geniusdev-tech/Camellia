'use client'

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ExternalLink, Github, RefreshCw, ShieldCheck } from 'lucide-react'
import { githubAPI } from '@/lib/api'
import { useAuthStore } from '@/store/auth'

export default function SettingsPage() {
  const qc = useQueryClient()
  const { user } = useAuthStore()
  const githubLinked = Boolean(user?.github_id || user?.githubId)

  const dashboardQuery = useQuery({
    queryKey: ['github', 'dashboard', 'settings-view'],
    queryFn: () => githubAPI.dashboard({ scope: 'all', sortBy: 'updated', issuesThreshold: 10 }),
    enabled: githubLinked,
    staleTime: 45_000,
    retry: 1,
  })

  const profileQuery = useQuery({
    queryKey: ['github', 'profile', 'settings-view'],
    queryFn: githubAPI.profile,
    enabled: githubLinked,
    staleTime: 60_000,
    retry: 1,
  })

  const syncMutation = useMutation({
    mutationFn: githubAPI.sync,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['github'] }),
  })

  if (!githubLinked) {
    return (
      <div className="social-page">
        <section className="social-hero">
          <h1 className="text-3xl font-bold text-slate-100">Configurações GitHub</h1>
          <p className="mt-2 text-sm text-slate-300">Conecte sua conta para ver status de sync e metadados do perfil.</p>
        </section>
      </div>
    )
  }

  const profile = profileQuery.data?.profile
  const dashboard = dashboardQuery.data

  return (
    <div className="social-page space-y-4">
      <section className="social-hero">
        <div className="social-hero-content">
          <div className="hero-badge">Settings</div>
          <h1 className="mt-3 text-3xl font-semibold text-white">Conta conectada e sincronização</h1>
          <p className="mt-2 text-sm text-slate-300">Metadados e status do perfil GitHub.</p>
        </div>
        <div className="social-hero-cta">
          <button onClick={() => syncMutation.mutate()} disabled={syncMutation.isPending} className="h-btn-primary">
            <RefreshCw className={`h-4 w-4 ${syncMutation.isPending ? 'animate-spin' : ''}`} />
            Sincronizar agora
          </button>
        </div>
      </section>

      <section className="grid gap-3 lg:grid-cols-2">
        <div className="social-side-card">
          <div className="inline-flex items-center gap-2">
            <Github className="h-4 w-4 text-orange-300" />
            <p className="text-xs font-mono uppercase tracking-[0.18em] text-slate-400">Perfil</p>
          </div>

          {profile ? (
            <div className="mt-3 flex items-start gap-3">
              <img src={profile.avatarUrl} alt={profile.login} className="h-14 w-14 rounded-full border border-slate-600/70 object-cover" />
              <div className="min-w-0">
                <p className="truncate text-base font-semibold text-slate-100">{profile.name || profile.login}</p>
                <a href={profile.htmlUrl} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs text-orange-300 hover:text-orange-200">
                  @{profile.login} <ExternalLink className="h-3 w-3" />
                </a>
                <p className="mt-2 text-xs text-slate-400">{profile.followers} seguidores • {profile.following} seguindo • {profile.publicRepos} repos públicos</p>
                {profile.bio ? <p className="mt-2 text-sm text-slate-300">{profile.bio}</p> : null}
              </div>
            </div>
          ) : (
            <p className="mt-3 text-sm text-slate-400">Perfil indisponível.</p>
          )}
        </div>

        <div className="social-side-card">
          <div className="inline-flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-orange-300" />
            <p className="text-xs font-mono uppercase tracking-[0.18em] text-slate-400">Status de integração</p>
          </div>
          <div className="mt-3 space-y-2 text-sm text-slate-300">
            <div className="flex justify-between"><span>Token</span><span className="font-semibold text-slate-100">{dashboard?.tokenStatus === 'expired' ? 'Expirado' : 'OK'}</span></div>
            <div className="flex justify-between"><span>Repos em cache</span><span className="font-semibold text-slate-100">{dashboard?.sync.cachedRepos ?? 0}</span></div>
            <div className="flex justify-between"><span>Último sync</span><span className="font-semibold text-slate-100">{dashboard?.sync.lastSyncedAt ? new Date(dashboard.sync.lastSyncedAt).toLocaleString('pt-BR') : 'N/A'}</span></div>
            <div className="flex justify-between"><span>Com branch protection</span><span className="font-semibold text-slate-100">{dashboard?.security.withBranchProtection ?? 0}</span></div>
          </div>
        </div>
      </section>

      {dashboard?.quickActions.githubProfileUrl ? (
        <a href={dashboard.quickActions.githubProfileUrl} target="_blank" rel="noreferrer" className="h-btn inline-flex">
          Abrir perfil no GitHub <ExternalLink className="h-4 w-4" />
        </a>
      ) : null}
    </div>
  )
}
