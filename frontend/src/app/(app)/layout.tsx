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
      className={`flex flex-col h-full w-64 bg-dark-850/80 backdrop-blur-xl border-r border-white/[0.05] ${
        mobile ? '' : ''
      }`}
    >
      {/* Logo */}
      <div className="h-16 flex items-center gap-3 px-5 border-b border-white/[0.05]">
        <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-primary-600 to-accent-500 flex items-center justify-center shrink-0">
          <FolderKanban className="w-4 h-4 text-white" />
        </div>
        <div className="min-w-0">
          <p className="text-sm font-bold text-white font-display leading-none">GateStack</p>
          <p className="text-[10px] text-gray-500 mt-0.5">The access control stack</p>
        </div>
        <TauriStatus className="ml-auto" />
      </div>

      {/* Nav */}
      <nav className="flex-1 py-4 px-3 space-y-0.5">
        <p className="px-3 mb-2 text-[10px] font-semibold text-gray-600 uppercase tracking-widest">
          Principal
        </p>
        {NAV.filter((item) => !item.ownerOnly || canManageOwnerActions(user?.role)).map(({ href, label, icon: Icon }) => {
          const active = pathname === href || pathname.startsWith(href + '/')
          return (
            <Link
              key={href}
              href={href}
              onClick={() => setOpen(false)}
              className={`flex items-center gap-3 px-3 py-2 rounded-xl text-sm font-medium transition-all group ${
                active
                  ? 'bg-primary-600/20 text-white border border-primary-500/20'
                  : 'text-gray-400 hover:text-white hover:bg-dark-700'
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
        <div className="p-3 border-t border-white/[0.05]">
          <div className="flex items-center gap-3 px-3 py-2 mb-1 rounded-xl bg-dark-800/50">
            <div className="w-8 h-8 rounded-full bg-gradient-to-br from-primary-500 to-accent-500 flex items-center justify-center shrink-0 text-xs font-bold text-white">
              {user.email[0].toUpperCase()}
            </div>
            <div className="min-w-0 flex-1">
              <p className="text-xs font-medium text-white truncate">{user.email}</p>
              <p className="text-[10px] text-gray-500">{user.role || 'user'} · {user.has_2fa ? '2FA ativo' : '2FA inativo'}</p>
            </div>
          </div>
          <button
            onClick={handleLogout}
            className="flex items-center gap-2 w-full px-3 py-2 text-sm text-gray-500 hover:text-red-400 hover:bg-red-500/10 rounded-xl transition-all"
          >
            <LogOut className="w-3.5 h-3.5" />
            Sair
          </button>
        </div>
      )}
    </aside>
  )

  return (
    <div className="flex h-screen overflow-hidden bg-dark-900">
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
        <header className="h-16 shrink-0 flex items-center justify-between px-4 lg:px-6 border-b border-white/[0.05] bg-dark-850/50 backdrop-blur-xl">
          <button
            onClick={() => setOpen(true)}
            className="lg:hidden p-2 rounded-xl text-gray-400 hover:text-white hover:bg-dark-700 transition-all"
          >
            <Menu className="w-5 h-5" />
          </button>

          <div className="flex-1 lg:flex-none" />

          <div className="flex items-center gap-1">
            <button className="p-2 rounded-xl text-gray-500 hover:text-white hover:bg-dark-700 transition-all">
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
              className="p-2 rounded-xl text-gray-500 hover:text-white hover:bg-dark-700 transition-all"
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
          >
            {children}
          </motion.div>
        </main>
      </div>
    </div>
  )
}
