'use client'

import Link from 'next/link'
import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, ShieldCheck } from 'lucide-react'
import { githubAPI } from '@/lib/api'
import { useAuthStore } from '@/store/auth'

export default function OpsPage() {
  const { user } = useAuthStore()
  const githubLinked = Boolean(user?.github_id || user?.githubId)

  const dashboardQuery = useQuery({
    queryKey: ['github', 'dashboard', 'ops-view'],
    queryFn: () => githubAPI.dashboard({ scope: 'all', sortBy: 'updated', issuesThreshold: 10 }),
    enabled: githubLinked,
    staleTime: 45_000,
    retry: 1,
  })

  const data = dashboardQuery.data

  if (!githubLinked) {
    return (
      <div className="social-page">
        <section className="social-hero">
          <h1 className="text-3xl font-bold text-slate-100">Operações via GitHub</h1>
          <p className="mt-2 text-sm text-slate-300">Conecte sua conta para visualizar saúde e segurança dos repositórios.</p>
          <Link href="/login" className="mt-4 inline-flex rounded-xl border border-orange-400/35 bg-orange-500/15 px-4 py-2 text-sm text-orange-100">Ir para login</Link>
        </section>
      </div>
    )
  }

  return (
    <div className="social-page space-y-4">
      <section className="social-hero">
        <div className="social-hero-content">
          <div className="hero-badge">GitHub Ops</div>
          <h1 className="mt-3 text-3xl font-semibold text-white">Saúde e segurança dos repositórios</h1>
          <p className="mt-2 text-sm text-slate-300">Indicadores operacionais do dashboard oficial do GitHub.</p>
        </div>
        <div className="social-hero-cta">
          <p className="text-xs text-slate-400">Monitore filas e métricas em um único feed.</p>
        </div>
      </section>

      {dashboardQuery.isLoading && <p className="text-sm text-slate-400">Carregando dados...</p>}
      {dashboardQuery.isError && <p className="rounded-xl border border-amber-400/30 bg-amber-400/10 px-3 py-2 text-sm text-amber-200">Falha ao carregar dados de operação.</p>}

      {data && (
        <>
          <section className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <div className="social-tile"><p className="text-[11px] text-slate-400">Sem descrição</p><p className="mt-1 text-xl font-semibold text-slate-100">{data.health.reposWithoutDescription}</p></div>
            <div className="social-tile"><p className="text-[11px] text-slate-400">Sem licença</p><p className="mt-1 text-xl font-semibold text-slate-100">{data.health.reposWithoutLicense}</p></div>
            <div className="social-tile"><p className="text-[11px] text-slate-400">Issues críticas</p><p className="mt-1 text-xl font-semibold text-slate-100">{data.health.reposWithOpenIssuesAboveThreshold}</p></div>
            <div className="social-tile"><p className="text-[11px] text-slate-400">Branch protection</p><p className="mt-1 text-xl font-semibold text-slate-100">{data.security.withBranchProtection}/{data.security.scannedRepos}</p></div>
          </section>

          <section className="grid gap-3 lg:grid-cols-2">
            <div className="social-side-card">
              <div className="inline-flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-orange-300" />
                <p className="text-xs font-mono uppercase tracking-[0.18em] text-slate-400">Segurança</p>
              </div>
              <div className="mt-3 space-y-2 text-sm text-slate-300">
                <div className="flex justify-between"><span>Sem proteção</span><span>{data.security.withoutBranchProtection}</span></div>
                <div className="flex justify-between"><span>Dependabot</span><span>{data.security.dependabotAvailable ? String(data.security.reposWithDependabotAlerts ?? 0) : 'N/A'}</span></div>
                <div className="flex justify-between"><span>Code scanning</span><span>{data.security.codeScanningAvailable ? String(data.security.reposWithCodeScanningAlerts ?? 0) : 'N/A'}</span></div>
              </div>
            </div>

            <div className="social-side-card">
              <div className="inline-flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-amber-300" />
                <p className="text-xs font-mono uppercase tracking-[0.18em] text-slate-400">Distribuição por linguagem</p>
              </div>
              <div className="mt-3 space-y-2">
                {data.health.languages.length === 0 ? <p className="text-sm text-slate-400">Sem dados.</p> : null}
                {data.health.languages.map((item) => (
                  <div key={item.language} className="social-tile flex items-center justify-between">
                    <span className="text-sm text-slate-200">{item.language}</span>
                    <span className="text-xs text-slate-400">{item.count}</span>
                  </div>
                ))}
              </div>
            </div>
          </section>
        </>
      )}
    </div>
  )
}
