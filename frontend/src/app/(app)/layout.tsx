'use client'

import { useEffect, useMemo, useState } from 'react'
import { useRouter, usePathname } from 'next/navigation'
import Link from 'next/link'
import { motion, AnimatePresence } from 'framer-motion'
import { useQuery } from '@tanstack/react-query'
import {
  Bell,
  BookOpen,
  FolderGit2,
  Globe2,
  Home,
  LogOut,
  Menu,
  Settings,
  Sparkles,
  Users,
  Workflow,
  X,
} from 'lucide-react'
import { useAuthStore } from '@/store/auth'
import { authAPI, githubAPI } from '@/lib/api'
import { TauriStatus } from '@/components/TauriStatus'
import { canManageOwnerActions } from '@/lib/ui'

const NAV = [
  { href: '/dashboard', label: 'Início', icon: Home, ownerOnly: false },
  { href: '/repository', label: 'Repositório', icon: FolderGit2, ownerOnly: false },
  { href: '/teams', label: 'Times', icon: Users, ownerOnly: false },
  { href: '/ops', label: 'Operações', icon: Workflow, ownerOnly: false },
  { href: '/catalog', label: 'Descobrir', icon: Globe2, ownerOnly: false },
  { href: '/settings', label: 'Configurações', icon: Settings, ownerOnly: false },
]

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter()
  const pathname = usePathname()
  const { user, isAuthenticated, logout } = useAuthStore()
  const [open, setOpen] = useState(false)
  const githubLinked = Boolean(user?.github_id || user?.githubId)

  const githubProfileQuery = useQuery({
    queryKey: ['github', 'profile'],
    queryFn: githubAPI.profile,
    enabled: githubLinked,
    staleTime: 60_000,
    retry: 1,
  })
  const githubReposQuery = useQuery({
    queryKey: ['github', 'repos', 'layout'],
    queryFn: githubAPI.repos,
    enabled: githubLinked,
    staleTime: 60_000,
    retry: 1,
  })

  useEffect(() => {
    if (!isAuthenticated) router.replace('/login')
  }, [isAuthenticated, router])

  const handleLogout = async () => {
    try {
      await authAPI.logout()
    } catch {}
    logout()
    router.replace('/login')
  }

  const currentTitle = useMemo(() => {
    const hit = NAV.find((item) => pathname === item.href || pathname.startsWith(item.href + '/'))
    return hit?.label || 'GateStack'
  }, [pathname])
  const topLanguages = useMemo(() => {
    const counter = new Map<string, number>()
    for (const repo of githubReposQuery.data?.repos ?? []) {
      const language = repo.language || 'N/A'
      counter.set(language, (counter.get(language) || 0) + 1)
    }
    return [...counter.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5)
  }, [githubReposQuery.data?.repos])
  const recentRepositories = useMemo(
    () => [...(githubReposQuery.data?.repos ?? [])]
      .sort((a, b) => new Date(b.dbUpdatedAt).getTime() - new Date(a.dbUpdatedAt).getTime())
      .slice(0, 4),
    [githubReposQuery.data?.repos],
  )

  if (!isAuthenticated) return null

  const LeftRail = ({ mobile = false }: { mobile?: boolean }) => (
    <aside className={`social-left-rail ${mobile ? 'h-full w-[86vw] max-w-[320px]' : ''}`}>
      <div className="social-brand-row">
        <div className="social-logo-pill">
          <Sparkles className="h-4 w-4" />
        </div>
        <div>
          <p className="social-brand-name">GateStack Social</p>
          <p className="social-brand-sub">repo.network</p>
        </div>
        <TauriStatus className="ml-auto" />
        {mobile && (
          <button onClick={() => setOpen(false)} className="social-icon-btn ml-1" aria-label="Fechar menu">
            <X className="h-4 w-4" />
          </button>
        )}
      </div>

      <nav className="mt-3 space-y-1">
        {NAV.filter((item) => !item.ownerOnly || canManageOwnerActions(user?.role)).map(({ href, label, icon: Icon }) => {
          const active = pathname === href || pathname.startsWith(href + '/')
          return (
            <Link
              key={href}
              href={href}
              onClick={() => setOpen(false)}
              className={`social-nav-item ${active ? 'active' : ''}`}
            >
              <Icon className="h-4 w-4" />
              <span>{label}</span>
            </Link>
          )
        })}
      </nav>

      <div className="social-left-footer">
        <div className="social-user-chip">
          {user?.avatarUrl ? (
            <img src={user.avatarUrl} alt={user.name || user.email} className="social-avatar" />
          ) : (
            <div className="social-avatar social-avatar-fallback">{(user?.email?.[0] || 'G').toUpperCase()}</div>
          )}
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-semibold text-slate-100">{user?.name || user?.email}</p>
            <p className="truncate text-xs text-slate-400">@{(user?.email || 'user').split('@')[0]}</p>
          </div>
        </div>

        {githubProfileQuery.data?.profile && (
          <div className="social-mini-card">
            <p className="text-[10px] uppercase tracking-[0.18em] text-slate-400">GitHub</p>
            <p className="mt-1 text-xs text-slate-200">
              {githubProfileQuery.data.profile.followers} seguidores • {githubProfileQuery.data.profile.publicRepos} repos
            </p>
          </div>
        )}

        <button onClick={handleLogout} className="social-logout-btn">
          <LogOut className="h-3.5 w-3.5" />
          Sair
        </button>
      </div>
    </aside>
  )

  return (
    <div className="social-shell">
      <div className="hidden lg:block">
        <LeftRail />
      </div>

      <AnimatePresence>
        {open && (
          <>
            <motion.button
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setOpen(false)}
              className="fixed inset-0 z-40 bg-slate-950/70 backdrop-blur-sm lg:hidden"
              aria-label="Fechar menu"
            />
            <motion.div
              initial={{ x: '-100%' }}
              animate={{ x: 0 }}
              exit={{ x: '-100%' }}
              transition={{ type: 'spring', damping: 28, stiffness: 280 }}
              className="fixed inset-y-0 left-0 z-50 lg:hidden"
            >
              <LeftRail mobile />
            </motion.div>
          </>
        )}
      </AnimatePresence>

      <section className="social-main-column">
        <header className="social-topbar">
          <div className="flex items-center gap-2">
            <button onClick={() => setOpen(true)} className="social-icon-btn lg:hidden" aria-label="Abrir menu">
              <Menu className="h-5 w-5" />
            </button>
            <p className="text-sm font-semibold text-slate-100">{currentTitle}</p>
          </div>

          <div className="flex items-center gap-1.5">
            <button className="social-icon-btn" aria-label="Notificações">
              <Bell className="h-4 w-4" />
            </button>
            <button
              onClick={() => {
                if (typeof window !== 'undefined' && (window as unknown as { __TAURI__?: unknown }).__TAURI__) {
                  import('@tauri-apps/api/core').then(({ invoke }) => invoke('open_docs').catch(console.error))
                } else {
                  window.open('/docs', '_blank')
                }
              }}
              className="social-icon-btn"
              aria-label="Abrir documentação"
            >
              <BookOpen className="h-4 w-4" />
            </button>
          </div>
        </header>

        <main className="social-feed-scroll">
          <motion.div key={pathname} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.2 }}>
            {children}
          </motion.div>
        </main>
      </section>

      <aside className="social-right-rail hidden xl:block">
        <div className="social-right-card">
          <p className="social-right-title">Linguagens</p>
          <div className="mt-3 space-y-2">
            {topLanguages.length === 0 ? <p className="text-xs text-slate-500">Sem dados do GitHub.</p> : null}
            {topLanguages.map(([language, count]) => (
              <div key={language} className="social-trend-item flex items-center justify-between">
                <span>{language}</span>
                <span className="text-xs text-slate-400">{count}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="social-right-card">
          <p className="social-right-title">Repos Recentes</p>
          <div className="mt-3 space-y-2">
            {recentRepositories.length === 0 ? <p className="text-xs text-slate-500">Nenhum repositório sincronizado.</p> : null}
            {recentRepositories.map((repo) => (
              <a key={repo.id} href={repo.htmlUrl} target="_blank" rel="noreferrer" className="social-trend-item block">
                <p className="truncate text-xs text-slate-100">{repo.fullName}</p>
                <p className="mt-0.5 text-[11px] text-slate-500">{new Date(repo.dbUpdatedAt).toLocaleDateString('pt-BR')}</p>
              </a>
            ))}
          </div>
        </div>
      </aside>
    </div>
  )
}
