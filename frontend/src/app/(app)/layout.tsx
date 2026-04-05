'use client'
import { useEffect, useState } from 'react'
import { useRouter, usePathname } from 'next/navigation'
import Link from 'next/link'
import { motion, AnimatePresence } from 'framer-motion'
import {
  FolderKanban, LayoutDashboard, Settings, LogOut,
  Menu, ChevronRight, Bell, HelpCircle,
  FolderGit2, Users, ActivitySquare, Globe2, X,
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

  const Sidebar = ({ mobile = false }: { mobile?: boolean }) => (
    <aside className={`relative flex h-full w-64 flex-col glass ${mobile ? 'rounded-none' : 'rounded-none lg:rounded-r-2xl'}`}>
      {/* Logo */}
      <div className="flex h-16 items-center gap-3 border-b border-white/5 px-5">
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-green-400/20 to-cyan-400/20 border border-green-400/15">
          <FolderKanban className="w-4.5 h-4.5 text-green-400" />
        </div>
        <div className="min-w-0">
          <p className="font-display text-sm font-bold leading-none bg-gradient-to-r from-green-400 to-cyan-400 bg-clip-text text-transparent">
            GateStack
          </p>
          <p className="mt-0.5 font-mono text-[10px] text-gray-500">ops://access-ctrl</p>
        </div>
        <TauriStatus className="ml-auto" />
        {mobile && (
          <button onClick={() => setOpen(false)} className="ml-1 p-1 rounded-lg text-gray-500 hover:text-white hover:bg-white/5 transition-all">
            <X className="h-4 w-4" />
          </button>
        )}
      </div>

      {/* Nav */}
      <nav className="flex-1 py-4 px-3 space-y-0.5 overflow-y-auto">
        <p className="mb-2.5 px-3 font-mono text-[10px] font-semibold uppercase tracking-[0.2em] text-gray-500">
          Principal
        </p>
        {NAV.filter((item) => !item.ownerOnly || canManageOwnerActions(user?.role)).map(({ href, label, icon: Icon }) => {
          const active = pathname === href || pathname.startsWith(href + '/')
          return (
            <Link
              key={href}
              href={href}
              onClick={() => setOpen(false)}
              className={`group flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-medium transition-all duration-200 ${
                active
                  ? 'bg-cyan-400/8 text-white border border-cyan-400/15'
                  : 'text-gray-400 hover:bg-white/4 hover:text-gray-200 border border-transparent'
              }`}
            >
              <Icon className={`w-4 h-4 shrink-0 transition-colors ${active ? 'text-cyan-400' : 'text-gray-500 group-hover:text-gray-300'}`} />
              {label}
              {active && <ChevronRight className="w-3 h-3 ml-auto text-cyan-400/60" />}
            </Link>
          )
        })}
      </nav>

      {/* User footer */}
      {user && (
        <div className="border-t border-white/5 p-3">
          <div className="mb-2 flex items-center gap-3 rounded-xl bg-white/3 border border-white/5 px-3 py-2.5">
            {user.avatarUrl ? (
              <img src={user.avatarUrl} alt={user.name || user.email} className="h-8 w-8 shrink-0 rounded-full object-cover border border-white/10" />
            ) : (
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-green-400/25 to-cyan-400/25 text-xs font-bold text-white">
                {user.email[0].toUpperCase()}
              </div>
            )}
            <div className="min-w-0 flex-1">
              <p className="text-xs font-medium text-white truncate">{user.name || user.email}</p>
              <p className="font-mono text-[10px] text-gray-500">
                {user.role || 'user'} · {user.has_2fa ? '2FA ✓' : '2FA ✗'}
              </p>
            </div>
          </div>
          <div className="mb-2">
            <span className="online-chip">
              <span className="online-dot" />
              online
            </span>
          </div>
          <button
            onClick={handleLogout}
            className="flex w-full items-center gap-2 rounded-xl px-3 py-2 text-sm text-gray-500 transition-all hover:bg-red-500/8 hover:text-red-400"
          >
            <LogOut className="w-3.5 h-3.5" />
            Sair
          </button>
        </div>
      )}
    </aside>
  )

  return (
    <div className="flex h-screen overflow-hidden">
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
        <header className="flex h-14 shrink-0 items-center justify-between border-b border-white/5 px-4 lg:px-6 glass-subtle" style={{ borderRadius: 0 }}>
          <button
            onClick={() => setOpen(true)}
            className="rounded-xl p-2 text-gray-500 transition-all hover:bg-white/5 hover:text-white lg:hidden"
          >
            <Menu className="w-5 h-5" />
          </button>

          <div className="flex-1 lg:flex-none" />

          <div className="mr-3 hidden md:flex">
            <span className="online-chip">
              <span className="online-dot" />
              online
            </span>
          </div>

          <div className="flex items-center gap-1">
            <button className="rounded-xl p-2 text-gray-500 transition-all hover:bg-white/5 hover:text-white">
              <Bell className="w-4 h-4" />
            </button>
            <button
              onClick={() => {
                if (typeof window !== 'undefined' && (window as unknown as { __TAURI__?: unknown }).__TAURI__) {
                  import('@tauri-apps/api/core').then(({ invoke }) =>
                    invoke('open_docs').catch(console.error)
                  )
                } else {
                  window.open('/docs', '_blank')
                }
              }}
              className="rounded-xl p-2 text-gray-500 transition-all hover:bg-white/5 hover:text-white"
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
