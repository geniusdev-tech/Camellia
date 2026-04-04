'use client'
import { useEffect, useState } from 'react'
import { useRouter, usePathname } from 'next/navigation'
import Link from 'next/link'
import { motion, AnimatePresence } from 'framer-motion'
import {
  FolderKanban, LayoutDashboard, Settings, LogOut,
  Menu, ChevronRight, Bell, HelpCircle,
  FolderGit2, Users, ActivitySquare, Globe2,
} from 'lucide-react'
import { useAuthStore } from '@/store/auth'
import { authAPI } from '@/lib/api'
import { TauriStatus } from '@/components/TauriStatus'
import { canManageOwnerActions } from '@/lib/ui'

const NAV = [
  { href: '/dashboard', label: 'Visão Geral', icon: LayoutDashboard, ownerOnly: false },
  { href: '/repository', label: 'Repositório', icon: FolderGit2, ownerOnly: false },
  { href: '/teams', label: 'Times', icon: Users, ownerOnly: false },
  { href: '/ops', label: 'Operações', icon: ActivitySquare, ownerOnly: false },
  { href: '/catalog', label: 'Catálogo', icon: Globe2, ownerOnly: false },
  { href: '/settings', label: 'Conta', icon: Settings, ownerOnly: false },
]

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const router    = useRouter()
  const pathname  = usePathname()
  const { user, isAuthenticated, logout } = useAuthStore()
  const [open, setOpen] = useState(false)

  useEffect(() => {
    if (!isAuthenticated) router.replace('/login')
  }, [isAuthenticated, router])

  const handleLogout = async () => {
    try { await authAPI.logout() } catch {}
    logout()
    router.replace('/login')
  }

  if (!isAuthenticated) return null

  const Sidebar = ({ mobile = false }) => (
    <aside
      className={`relative scanline-overlay hacker-shell hacker-grid flex h-full w-64 flex-col border-r border-green-400/20 ${
        mobile ? '' : ''
      }`}
    >
      {/* Logo */}
      <div className="flex h-16 items-center gap-3 border-b border-green-400/20 px-5">
        <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-gradient-to-br from-primary-600 to-accent-500 cyber-glow-cyan">
          <FolderKanban className="w-4 h-4 text-white" />
        </div>
        <div className="min-w-0">
          <p className="font-display text-sm font-bold leading-none text-white glitch-hover">GateStack</p>
          <p className="mt-0.5 font-mono text-[10px] text-green-300/75">ops://access-control</p>
        </div>
        <TauriStatus className="ml-auto" />
      </div>

      {/* Nav */}
      <nav className="flex-1 py-4 px-3 space-y-0.5">
        <p className="mb-2 px-3 font-mono text-[10px] font-semibold uppercase tracking-widest text-green-300/70">
          Principal
        </p>
        {NAV.filter((item) => !item.ownerOnly || canManageOwnerActions(user?.role)).map(({ href, label, icon: Icon }) => {
          const active = pathname === href || pathname.startsWith(href + '/')
          return (
            <Link
              key={href}
              href={href}
              onClick={() => setOpen(false)}
              className={`group flex items-center gap-3 rounded-xl px-3 py-2 text-sm font-medium transition-all ${
                active
                  ? 'border border-cyan-400/30 bg-cyan-400/10 text-white cyber-glow-cyan'
                  : 'text-gray-400 hover:border hover:border-green-400/20 hover:bg-dark-800/80 hover:text-white'
              }`}
            >
              <Icon className={`w-4 h-4 shrink-0 ${active ? 'text-accent' : 'group-hover:text-accent'} transition-colors`} />
              {label}
              {active && <ChevronRight className="w-3 h-3 ml-auto text-accent opacity-70" />}
            </Link>
          )
        })}
      </nav>

      {/* User footer */}
      {user && (
        <div className="border-t border-green-400/20 p-3">
          <div className="mb-2 flex items-center gap-3 rounded-xl border border-green-400/20 bg-dark-800/70 px-3 py-2">
            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-primary-500 to-accent-500 text-xs font-bold text-white">
              {user.email[0].toUpperCase()}
            </div>
            <div className="min-w-0 flex-1">
              <p className="text-xs font-medium text-white truncate">{user.email}</p>
              <p className="font-mono text-[10px] text-green-300/70">{user.role || 'user'} · {user.has_2fa ? '2FA ativo' : '2FA inativo'}</p>
            </div>
          </div>
          <div className="mb-2 online-chip">
            <span className="online-dot" />
            online
          </div>
          <button
            onClick={handleLogout}
            className="flex w-full items-center gap-2 rounded-xl px-3 py-2 text-sm text-gray-400 transition-all hover:bg-red-500/10 hover:text-red-400"
          >
            <LogOut className="w-3.5 h-3.5" />
            Sair
          </button>
        </div>
      )}
    </aside>
  )

  return (
    <div className="hacker-grid flex h-screen overflow-hidden bg-dark-900">
      {/* Desktop sidebar */}
      <div className="hidden lg:flex shrink-0">
        <Sidebar />
      </div>

      {/* Mobile drawer */}
      <AnimatePresence>
        {open && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setOpen(false)}
              className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40 lg:hidden"
            />
            <motion.div
              initial={{ x: '-100%' }}
              animate={{ x: 0 }}
              exit={{ x: '-100%' }}
              transition={{ type: 'spring', damping: 30, stiffness: 300 }}
              className="fixed inset-y-0 left-0 z-50 lg:hidden"
            >
              <Sidebar mobile />
            </motion.div>
          </>
        )}
      </AnimatePresence>

      {/* Main */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top bar */}
        <header className="relative scanline-overlay flex h-16 shrink-0 items-center justify-between border-b border-green-400/20 bg-dark-900/80 px-4 backdrop-blur-xl lg:px-6">
          <button
            onClick={() => setOpen(true)}
            className="rounded-xl p-2 text-gray-400 transition-all hover:bg-dark-700 hover:text-white lg:hidden"
          >
            <Menu className="w-5 h-5" />
          </button>

          <div className="flex-1 lg:flex-none" />

          <div className="mr-3 hidden md:flex">
            <div className="online-chip">
              <span className="online-dot" />
              online
            </div>
          </div>

          <div className="flex items-center gap-1">
            <button className="rounded-xl p-2 text-gray-500 transition-all hover:bg-dark-700 hover:text-white">
              <Bell className="w-4 h-4" />
            </button>
            <button
              onClick={() => {
                // Open docs in Tauri or new tab
                if (typeof window !== 'undefined' && (window as unknown as { __TAURI__?: unknown }).__TAURI__) {
                  import('@tauri-apps/api/core').then(({ invoke }) =>
                    invoke('open_docs').catch(console.error)
                  )
                } else {
                  window.open('/docs', '_blank')
                }
              }}
              className="rounded-xl p-2 text-gray-500 transition-all hover:bg-dark-700 hover:text-white"
              title="Ajuda"
            >
              <HelpCircle className="w-4 h-4" />
            </button>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-y-auto p-4 lg:p-6">
          <motion.div
            key={pathname}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.2 }}
            className="relative"
          >
            {children}
          </motion.div>
        </main>
      </div>
    </div>
  )
}
