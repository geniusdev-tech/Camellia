'use client'
import { useState, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import { motion, AnimatePresence } from 'framer-motion'
import { FolderGit2, Eye, EyeOff, Loader2, AlertCircle, Sparkles, ArrowRight } from 'lucide-react'
import { authAPI } from '@/lib/api'
import { useAuthStore } from '@/store/auth'

type Mode = 'login' | 'register' | 'mfa'

export default function LoginPage() {
  const router  = useRouter()
  const setSession = useAuthStore((s) => s.setSession)

  const [mode, setMode]         = useState<Mode>('login')
  const [email, setEmail]       = useState('')
  const [password, setPassword] = useState('')
  const [mfaCode, setMfaCode]   = useState('')
  const [userId, setUserId]     = useState<number | string | null>(null)
  const [showPwd, setShowPwd]   = useState(false)
  const [loading, setLoading]   = useState(false)
  const [error, setError]       = useState('')

  const handleSubmit = useCallback(async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      if (mode === 'register') {
        const res = await authAPI.register({ email, password })
        if (res.success) {
          setMode('login')
          setPassword('')
          setError('')
        } else {
          setError(res.msg || 'Erro no registro')
        }
        return
      }

      if (mode === 'mfa') {
        if (!userId) { setError('Sessão inválida'); return }
        const res = await authAPI.loginMFA({ code: mfaCode, user_id: userId })
        if (res.success && res.access_token) {
          setSession({
            user_id: Number(res.user_id || userId),
            email: res.email || email,
            has_2fa: true,
            role: res.role || null,
          }, res.access_token, res.refresh_token)
          router.replace('/dashboard')
        } else {
          setError(res.msg || 'Código inválido')
        }
        return
      }

      // Normal login
      const res = await authAPI.login({ email, password })
      if (res.requires_mfa || res.requires_2fa) {
        setUserId(res.user_id ?? null)
        setMode('mfa')
      } else if (res.success && res.access_token) {
        setSession({
          user_id: Number(res.user_id || 0) || undefined,
          email: res.email || email,
          has_2fa: res.has_2fa || false,
          role: res.role || null,
        }, res.access_token, res.refresh_token)
        router.replace('/dashboard')
      } else {
        setError(res.msg || 'Credenciais inválidas')
      }
    } catch (err: unknown) {
      setError((err as Error).message || 'Erro de conexão')
    } finally {
      setLoading(false)
    }
  }, [mode, email, password, mfaCode, userId, setSession, router])

  return (
    <main className="min-h-screen flex items-center justify-center bg-dark-900 bg-grid-dark p-4">
      {/* Background glow */}
      <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
        <div className="w-[600px] h-[600px] rounded-full bg-primary/10 blur-[120px] opacity-60" />
      </div>

      <motion.div
        initial={{ opacity: 0, y: 24 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
        className="relative w-full max-w-sm"
      >
        {/* Card */}
        <div className="glass rounded-2xl p-8 shadow-panel">
          {/* Logo */}
          <div className="flex flex-col items-center mb-8">
            <div className="relative mb-4">
              <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-primary-600 to-accent-500 flex items-center justify-center shadow-glow-accent">
                <FolderGit2 className="w-8 h-8 text-white" />
              </div>
              <div className="absolute -bottom-1 -right-1 w-5 h-5 bg-accent rounded-full border-2 border-dark-900 flex items-center justify-center">
                <Sparkles className="w-2.5 h-2.5 text-dark-900" />
              </div>
            </div>
            <h1 className="text-xl font-bold tracking-tight font-display">GateStack</h1>
            <p className="text-xs text-gray-500 mt-0.5">The access control stack</p>
          </div>

          {/* Tab switcher (login / register) */}
          <AnimatePresence mode="wait">
            {mode !== 'mfa' && (
              <div className="flex mb-6 p-1 bg-dark-850 rounded-xl">
                {(['login', 'register'] as const).map((m) => (
                  <button
                    key={m}
                    type="button"
                    onClick={() => { setMode(m); setError('') }}
                    className={`flex-1 py-1.5 text-sm font-medium rounded-lg transition-all ${
                      mode === m
                        ? 'bg-dark-700 text-white shadow-md'
                        : 'text-gray-500 hover:text-gray-300'
                    }`}
                  >
                    {m === 'login' ? 'Entrar' : 'Registrar'}
                  </button>
                ))}
              </div>
            )}
          </AnimatePresence>

          {/* Error */}
          <AnimatePresence>
            {error && (
              <motion.div
                initial={{ opacity: 0, height: 0, marginBottom: 0 }}
                animate={{ opacity: 1, height: 'auto', marginBottom: 16 }}
                exit={{ opacity: 0, height: 0, marginBottom: 0 }}
                className="flex items-center gap-2 p-3 bg-danger/10 border border-danger/20 rounded-xl text-sm text-danger"
              >
                <AlertCircle className="w-4 h-4 shrink-0" />
                {error}
              </motion.div>
            )}
          </AnimatePresence>

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            {mode === 'mfa' ? (
              <>
                <div className="text-center mb-2">
                  <p className="text-sm text-gray-400">
                    Digite o código de 6 dígitos do seu autenticador:
                  </p>
                </div>
                <input
                  type="text"
                  inputMode="numeric"
                  maxLength={6}
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ''))}
                  placeholder="000 000"
                  className="w-full bg-dark-850 border border-white/10 rounded-xl px-4 py-3 text-center text-2xl tracking-[0.5em] font-mono text-white focus:outline-none focus:border-accent/50 focus:ring-1 focus:ring-accent/30 transition-all"
                  autoFocus
                  required
                />
                <button
                  type="button"
                  onClick={() => { setMode('login'); setMfaCode(''); setError('') }}
                  className="w-full text-xs text-gray-500 hover:text-gray-400 transition-colors"
                >
                  ← Voltar ao login
                </button>
              </>
            ) : (
              <>
                <div>
                  <label htmlFor="email" className="block text-xs font-medium text-gray-400 mb-1.5">Email</label>
                  <input
                    id="email"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="seu@email.com"
                    className="w-full bg-dark-850 border border-white/10 rounded-xl px-4 py-2.5 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-accent/50 focus:ring-1 focus:ring-accent/30 transition-all"
                    required
                  />
                </div>

                <div>
                  <label htmlFor="password" className="block text-xs font-medium text-gray-400 mb-1.5">Senha</label>
                  <div className="relative">
                    <input
                      id="password"
                      type={showPwd ? 'text' : 'password'}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="••••••••"
                      className="w-full bg-dark-850 border border-white/10 rounded-xl px-4 py-2.5 pr-10 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-accent/50 focus:ring-1 focus:ring-accent/30 transition-all"
                      required
                    />
                    <button
                      type="button"
                      onClick={() => setShowPwd((v) => !v)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300 transition-colors"
                    >
                      {showPwd ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>
              </>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 bg-gradient-to-r from-primary-600 to-accent-600 hover:from-primary-500 hover:to-accent-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium py-2.5 rounded-xl transition-all shadow-glow-primary text-sm"
            >
              {loading ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <>
                  {mode === 'login' ? 'Entrar' : mode === 'register' ? 'Criar conta' : 'Verificar'}
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>
        </div>

        <p className="text-center text-xs text-gray-600 mt-4">
          Coleção centralizada · uploads versionados · curadoria visual
        </p>
      </motion.div>
    </main>
  )
}
