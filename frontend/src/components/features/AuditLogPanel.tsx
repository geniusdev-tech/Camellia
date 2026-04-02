'use client'
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { RefreshCw, Shield, AlertTriangle, LogIn, LogOut, Lock, Unlock, KeyRound, CheckCircle2 } from 'lucide-react'
import { clsx } from 'clsx'
import { getApiBase } from '@/lib/tauri'

const ICON_MAP: Record<string, React.ElementType> = {
  'auth.login.success':   LogIn,
  'auth.login.failure':   AlertTriangle,
  'auth.logout':          LogOut,
  'auth.mfa.enabled':     KeyRound,
  'auth.mfa.success':     CheckCircle2,
  'auth.mfa.failure':     AlertTriangle,
  'crypto.file.encrypt':  Lock,
  'crypto.file.decrypt':  Unlock,
  'security.unauthorized_access': AlertTriangle,
}

const COLOR_MAP: Record<string, string> = {
  INFO:     'text-gray-400',
  WARNING:  'text-warning',
  ERROR:    'text-danger',
  CRITICAL: 'text-danger',
}

interface LogEntry {
  timestamp: string
  event_type: string
  user: string
  severity: string
  details: Record<string, unknown>
}

const LABEL_MAP: Record<string, string> = {
  'auth.login.success': 'Login autorizado',
  'auth.login.failure': 'Falha de login',
  'auth.logout': 'Logout',
  'auth.mfa.enabled': '2FA ativado',
  'auth.mfa.success': '2FA validado',
  'auth.mfa.failure': 'Falha no 2FA',
  'crypto.file.encrypt': 'Arquivo criptografado',
  'crypto.file.decrypt': 'Arquivo descriptografado',
}

export function AuditLogPanel() {
  const [loaded, setLoaded] = useState(false)
  const [typeFilter, setTypeFilter] = useState<'all' | 'auth' | 'crypto' | 'warning'>('all')

  const { data, isFetching, refetch } = useQuery({
    queryKey: ['audit-events'],
    enabled: loaded,
    queryFn: async () => {
      const base = await getApiBase()
      const token = typeof localStorage !== 'undefined'
        ? (JSON.parse(localStorage.getItem('camellia-auth') || '{}') as { state?: { accessToken?: string } })
            ?.state?.accessToken ?? ''
        : ''

      const res = await fetch(`${base}/api/audit/events`, {
        headers: {
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        credentials: 'include',
      })
      const payload = await res.json()
      return (payload.events ?? []) as LogEntry[]
    },
  })

  const entries = (data ?? []).filter((entry) => {
    if (typeFilter === 'all') return true
    if (typeFilter === 'auth') return entry.event_type.startsWith('auth.')
    if (typeFilter === 'crypto') return entry.event_type.startsWith('crypto.')
    return entry.severity !== 'INFO'
  })

  const filterTabs = [
    { value: 'all', label: 'Todos' },
    { value: 'auth', label: 'Auth' },
    { value: 'crypto', label: 'Cripto' },
    { value: 'warning', label: 'Alertas' },
  ] as const

  if (!loaded) {
    return (
      <button
        onClick={() => setLoaded(true)}
        className="flex items-center gap-2 text-sm text-gray-400 hover:text-white transition-colors"
      >
        <RefreshCw className="w-3.5 h-3.5" /> Carregar log de auditoria
      </button>
    )
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <p className="text-xs text-gray-500">{entries.length} eventos</p>
        <button onClick={() => refetch()} disabled={isFetching} className="p-1 rounded-lg hover:bg-dark-700 text-gray-500 hover:text-white transition-all">
          <RefreshCw className={`w-3 h-3 ${isFetching ? 'animate-spin' : ''}`} />
        </button>
      </div>

      <div className="flex flex-wrap gap-2">
        {filterTabs.map((tab) => (
          <button
            key={tab.value}
            onClick={() => setTypeFilter(tab.value)}
            className={clsx(
              'rounded-full border px-3 py-1 text-[11px] font-medium transition-all',
              typeFilter === tab.value
                ? 'border-primary-500/30 bg-primary-600/20 text-primary-200'
                : 'border-white/[0.06] bg-dark-800 text-gray-500 hover:text-white',
            )}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {entries.length === 0 && (
        <p className="text-xs text-gray-600 text-center py-4">Nenhum evento registrado.</p>
      )}

      <div className="max-h-48 overflow-y-auto space-y-1.5">
        {entries.map((e, i) => {
          const Icon = ICON_MAP[e.event_type] ?? Shield
          const colorClass = COLOR_MAP[e.severity] ?? 'text-gray-400'
          const ts = new Date(e.timestamp).toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' })
          return (
            <div key={i} className="flex items-start gap-3 p-3 rounded-xl bg-dark-850/60 border border-white/[0.04]">
              <Icon className={`w-3.5 h-3.5 mt-0.5 shrink-0 ${colorClass}`} />
              <div className="flex-1 min-w-0">
                <p className="text-xs text-white font-medium truncate">{e.event_type}</p>
                <p className="text-[11px] text-gray-300 mt-0.5">{LABEL_MAP[e.event_type] ?? e.event_type}</p>
                <p className="text-[10px] text-gray-500 mt-0.5">{ts} · {e.user}</p>
              </div>
              <span className={`text-[10px] font-medium ${colorClass}`}>{e.severity}</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}
