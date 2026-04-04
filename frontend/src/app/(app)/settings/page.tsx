'use client'
import { useState } from 'react'
import Link from 'next/link'
import { motion } from 'framer-motion'
import {
  Shield, ShieldCheck, ShieldX, QrCode, AlertTriangle,
  Lock, Key, Bell, Cpu, RefreshCw,
} from 'lucide-react'
import { authAPI } from '@/lib/api'
import { useAuthStore } from '@/store/auth'
import { MFASetupModal } from '@/components/features/MFASetupModal'
import { AuditLogPanel } from '@/components/features/AuditLogPanel'

export default function SettingsPage() {
  const { user, accessToken, refreshToken, setSession } = useAuthStore()
  const [mfaModal, setMfaModal]   = useState(false)
  const [loading, setLoading]     = useState(false)
  const [feedback, setFeedback]   = useState<{ type: 'ok' | 'err'; msg: string } | null>(null)

  const toast = (type: 'ok' | 'err', msg: string) => {
    setFeedback({ type, msg })
    setTimeout(() => setFeedback(null), 3500)
  }

  const disable2FA = async () => {
    if (!confirm('Desativar o 2FA reduz drasticamente a segurança. Confirmar?')) return
    setLoading(true)
    try {
      const res = await authAPI.disable2FA()
      if (res.success && user && accessToken) {
        setSession({ ...user, has_2fa: false }, accessToken, refreshToken)
        toast('ok', '2FA desativado.')
      } else {
        toast('err', res.msg || 'Erro')
      }
    } catch { toast('err', 'Erro de rede') }
    finally { setLoading(false) }
  }

  const sections = [
    {
      id: 'security',
      title: 'Autenticação',
      icon: Lock,
      content: (
        <div className="space-y-5">
          {/* 2FA Card */}
          <div className="flex items-start justify-between gap-4 p-5 rounded-2xl bg-dark-800/60 border border-white/[0.06]">
            <div className="flex items-start gap-4">
              <div className={`w-10 h-10 rounded-xl flex items-center justify-center shrink-0 ${
                user?.has_2fa ? 'bg-accent/15 text-accent' : 'bg-warning/15 text-warning'
              }`}>
                {user?.has_2fa ? <ShieldCheck className="w-5 h-5" /> : <ShieldX className="w-5 h-5" />}
              </div>
              <div>
                <p className="text-sm font-semibold text-white">Autenticação de Dois Fatores (TOTP)</p>
                <p className="text-xs text-gray-500 mt-0.5">
                  {user?.has_2fa
                    ? 'Ativo — conta protegida com autenticador TOTP.'
                    : 'Inativo — ative para proteger sua conta.'}
                </p>
                {user?.has_2fa && (
                  <span className="inline-flex items-center gap-1 mt-2 px-2 py-0.5 rounded-full bg-accent/10 text-accent text-[10px] font-medium border border-accent/20">
                    <ShieldCheck className="w-2.5 h-2.5" /> Verificado
                  </span>
                )}
              </div>
            </div>
            {user?.has_2fa ? (
              <button
                onClick={disable2FA}
                disabled={loading}
                className="shrink-0 flex items-center gap-2 px-4 py-2 rounded-xl bg-danger/10 hover:bg-danger/20 border border-danger/20 text-danger text-sm font-medium transition-all disabled:opacity-50"
              >
                <ShieldX className="w-3.5 h-3.5" />
                Desativar
              </button>
            ) : (
              <button
                onClick={() => setMfaModal(true)}
                className="shrink-0 flex items-center gap-2 px-4 py-2 rounded-xl bg-accent/10 hover:bg-accent/20 border border-accent/20 text-accent text-sm font-medium transition-all"
              >
                <QrCode className="w-3.5 h-3.5" />
                Ativar 2FA
              </button>
            )}
          </div>
        </div>
      ),
    },
    {
      id: 'crypto',
      title: 'Criptografia',
      icon: Key,
      content: (
        <div className="space-y-3">
          {[
            { label: 'Algoritmo de Cifra', value: 'AES-256-GCM / XChaCha20-Poly1305' },
            { label: 'KDF', value: 'Argon2id (t=3, m=64MB, p=4)' },
            { label: 'Integridade de Manifesto', value: 'Ed25519 + SHA-256' },
            { label: 'Proteção de Chave Mestra', value: 'Envelope KEK + AES-GCM' },
          ].map((row) => (
            <div key={row.label} className="flex items-center justify-between py-2.5 border-b border-white/[0.04] last:border-0">
              <span className="text-sm text-gray-400">{row.label}</span>
              <span className="text-sm text-white font-mono">{row.value}</span>
            </div>
          ))}
        </div>
      ),
    },
    {
      id: 'notifications',
      title: 'Notificações',
      icon: Bell,
      content: (
        <div className="space-y-3 text-sm text-gray-400">
          {[
            { label: 'Alerta de falha de login', default: true },
            { label: 'Confirmação de operação cripto', default: true },
            { label: 'Atualização de software', default: false },
          ].map((item) => (
            <div key={item.label} className="flex items-center justify-between">
              <span>{item.label}</span>
              <label className="relative inline-flex items-center cursor-pointer">
                <input type="checkbox" defaultChecked={item.default} className="sr-only peer" />
                <div className="w-9 h-5 bg-dark-700 rounded-full peer peer-checked:bg-accent peer-focus:outline-none transition-all after:content-[''] after:absolute after:top-0.5 after:left-0.5 after:bg-white after:rounded-full after:h-4 after:w-4 after:transition-all peer-checked:after:translate-x-4" />
              </label>
            </div>
          ))}
        </div>
      ),
    },
    {
      id: 'session',
      title: 'Sessão & Auto-Lock',
      icon: Cpu,
      content: (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-white">Timeout de inatividade</p>
              <p className="text-xs text-gray-500">Bloquear cofre após inatividade</p>
            </div>
            <select className="bg-dark-800 border border-white/10 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:border-accent/50">
              <option value="5">5 minutos</option>
              <option value="15">15 minutos</option>
              <option value="30">30 minutos</option>
              <option value="0">Nunca</option>
            </select>
          </div>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-white">Nível DII (Deep Integrity)</p>
              <p className="text-xs text-gray-500">Intensidade da inspeção de arquivos</p>
            </div>
            <select className="bg-dark-800 border border-white/10 rounded-xl px-3 py-2 text-sm text-white focus:outline-none focus:border-accent/50">
              <option value="standard">Padrão</option>
              <option value="paranoid">Paranoid</option>
            </select>
          </div>
        </div>
      ),
    },
    {
      id: 'audit',
      title: 'Log de Auditoria',
      icon: RefreshCw,
      content: <AuditLogPanel />,
    },
  ]

  return (
    <div className="social-page">
      <section className="social-hero">
        <p className="text-xs font-mono uppercase tracking-[0.2em] text-cyan-300">Feed da Conta</p>
        <h1 className="mt-2 text-3xl font-bold text-white">Conta, segurança e sessões</h1>
        <p className="mt-2 max-w-3xl text-sm text-gray-400">Controle 2FA, notificações, criptografia e ações sensíveis em um fluxo único.</p>
      </section>

      <section className="social-layout">
        <aside className="space-y-4">
          <div className="social-side-card">
            <p className="text-xs font-semibold uppercase tracking-widest text-gray-500">Acesso rápido</p>
            <div className="mt-3 space-y-2 text-sm text-gray-200">
              <Link href="/dashboard" className="block rounded-2xl bg-white/5 px-3 py-2 hover:bg-white/10">Voltar ao dashboard</Link>
              <Link href="/teams" className="block rounded-2xl bg-white/5 px-3 py-2 hover:bg-white/10">Gerir times</Link>
              <Link href="/ops" className="block rounded-2xl bg-white/5 px-3 py-2 hover:bg-white/10">Painel de operações</Link>
            </div>
          </div>
          <div className="social-side-card">
            <div className="inline-flex items-center gap-2 text-sm text-white">
              <ShieldCheck className="h-4 w-4 text-cyan-300" />
              Postura de segurança
            </div>
            <p className="mt-2 text-xs text-gray-500">Mantenha 2FA ativo e use logout global após alterações de credenciais.</p>
          </div>
        </aside>

        <main className="space-y-5">
          {feedback && (
            <motion.div
              initial={{ opacity: 0, y: -8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              className={`p-3 rounded-xl text-sm border ${
                feedback.type === 'ok'
                  ? 'bg-accent/10 border-accent/20 text-accent'
                  : 'bg-danger/10 border-danger/20 text-danger'
              }`}
            >
              {feedback.msg}
            </motion.div>
          )}

          {sections.map((sec) => (
            <section key={sec.id} className="glass rounded-2xl p-5 shadow-panel">
              <div className="flex items-center gap-2 mb-4 pb-4 border-b border-white/[0.05]">
                <sec.icon className="w-4 h-4 text-gray-400" />
                <h2 className="text-sm font-semibold text-white">{sec.title}</h2>
              </div>
              {sec.content}
            </section>
          ))}

          <section className="rounded-2xl p-5 border border-danger/30 bg-danger/5">
            <div className="flex items-center gap-2 mb-4">
              <AlertTriangle className="w-4 h-4 text-danger" />
              <h2 className="text-sm font-semibold text-danger">Zona de Emergência</h2>
            </div>
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="text-sm text-white font-medium">Limpeza de emergência</p>
                <p className="text-xs text-gray-500 mt-0.5">
                  Encerra a sessão e zera chaves da memória imediatamente.
                </p>
              </div>
              <button
                onClick={() => {
                  if (confirm('EMERGÊNCIA: Encerrar sessão agora?')) {
                    authAPI.logout().catch(() => {}).finally(() => {
                      useAuthStore.getState().logout()
                      window.location.href = '/login'
                    })
                  }
                }}
                className="shrink-0 px-4 py-2 rounded-xl bg-danger text-white text-sm font-bold hover:bg-danger-dark transition-all shadow-lg"
              >
                EXECUTAR WIPE
              </button>
            </div>
          </section>

          <section className="glass rounded-2xl p-5 shadow-panel">
            <div className="flex items-center gap-2 mb-4 pb-4 border-b border-white/[0.05]">
              <RefreshCw className="w-4 h-4 text-gray-400" />
              <h2 className="text-sm font-semibold text-white">Sessões</h2>
            </div>
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="text-sm text-white font-medium">Logout global</p>
                <p className="text-xs text-gray-500 mt-0.5">
                  Revoga todas as sessões de refresh token persistidas no backend.
                </p>
              </div>
              <button
                onClick={async () => {
                  setLoading(true)
                  try {
                    const res = await authAPI.logoutAll()
                    if (res.success) toast('ok', 'Todas as sessões foram encerradas.')
                    else toast('err', res.msg || 'Erro ao encerrar sessões.')
                  } catch {
                    toast('err', 'Erro de rede')
                  } finally {
                    setLoading(false)
                  }
                }}
                className="shrink-0 px-4 py-2 rounded-xl bg-primary-600/20 border border-primary-500/20 text-primary-200 text-sm font-medium"
              >
                Encerrar tudo
              </button>
            </div>
          </section>
        </main>

        <aside className="space-y-4">
          <div className="social-side-card">
            <div className="inline-flex items-center gap-2">
              <Bell className="h-4 w-4 text-orange-300" />
              <p className="text-xs font-semibold uppercase tracking-widest text-gray-500">Checklist</p>
            </div>
            <div className="mt-3 space-y-2 text-sm text-gray-200">
              <div className="rounded-2xl bg-white/5 px-3 py-2">2FA habilitado</div>
              <div className="rounded-2xl bg-white/5 px-3 py-2">Sessões revisadas</div>
              <div className="rounded-2xl bg-white/5 px-3 py-2">Convites monitorados</div>
            </div>
          </div>
          <div className="social-side-card">
            <div className="inline-flex items-center gap-2 text-sm text-white">
              <Key className="h-4 w-4 text-cyan-300" />
              Criptografia
            </div>
            <p className="mt-2 text-xs text-gray-500">Revise periodicamente política de chaves e parâmetros de KDF.</p>
          </div>
        </aside>
      </section>

      {/* 2FA Modal */}
      <MFASetupModal
        open={mfaModal}
        onClose={() => setMfaModal(false)}
        onSuccess={() => {
          if (user && accessToken) setSession({ ...user, has_2fa: true }, accessToken, refreshToken)
          setMfaModal(false)
          toast('ok', '2FA ativado com sucesso!')
        }}
      />
    </div>
  )
}
