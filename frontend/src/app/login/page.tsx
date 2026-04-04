'use client'

import { useCallback, useMemo, useState } from 'react'
import { useRouter } from 'next/navigation'
import { Eye, EyeOff, AlertCircle, Loader2 } from 'lucide-react'
import { authAPI } from '@/lib/api'
import { useAuthStore } from '@/store/auth'

type Mode = 'login' | 'register' | 'mfa'

export default function LoginPage() {
  const router = useRouter()
  const setSession = useAuthStore((state) => state.setSession)

  const [mode, setMode] = useState<Mode>('login')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [mfaCode, setMfaCode] = useState('')
  const [userId, setUserId] = useState<number | string | null>(null)
  const [showPwd, setShowPwd] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const ctaText = useMemo(() => {
    if (mode === 'register') return 'Criar Conta'
    if (mode === 'mfa') return 'Confirmar'
    return 'Entrar'
  }, [mode])

  const handleSubmit = useCallback(
    async (event: React.FormEvent) => {
      event.preventDefault()
      setError('')
      setLoading(true)

      try {
        if (mode === 'register') {
          const response = await authAPI.register({ email, password })
          if (response.success) {
            setMode('login')
            setPassword('')
            setError('')
          } else {
            setError(response.msg || response.message || 'Erro no registro')
          }
          return
        }

        if (mode === 'mfa') {
          if (!userId) {
            setError('Sessão inválida')
            return
          }
          const response = await authAPI.loginMFA({ code: mfaCode, user_id: userId })
          const token = response.accessToken || response.access_token
          if (response.success && token) {
            setSession(
              {
                user_id: Number(response.user_id || userId),
                email: response.email || email,
                has_2fa: true,
                role: response.role || null,
              },
              token,
              response.refresh_token,
            )
            router.replace('/dashboard')
          } else {
            setError(response.msg || response.message || 'Código inválido')
          }
          return
        }

        const loginResponse = await authAPI.login({ email, password })
        if (loginResponse.requires_mfa || loginResponse.requires_2fa) {
          setUserId(loginResponse.user_id ?? null)
          setMode('mfa')
        } else {
          const token = loginResponse.accessToken || loginResponse.access_token
          if (loginResponse.success && token) {
            setSession(
              {
                user_id: Number(loginResponse.user_id || 0) || undefined,
                email: loginResponse.email || email,
                has_2fa: loginResponse.has_2fa || false,
                role: loginResponse.role || null,
              },
              token,
              loginResponse.refresh_token,
            )
            router.replace('/dashboard')
          } else {
            setError(loginResponse.msg || loginResponse.message || 'Credenciais inválidas')
          }
        }
      } catch (err: unknown) {
        setError((err as Error).message || 'Erro de conexão')
      } finally {
        setLoading(false)
      }
    },
    [email, mfaCode, mode, password, router, setSession, userId],
  )

  return (
    <main className="min-h-screen bg-dark-950 flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="space-y-8">
          {/* Header */}
          <div className="text-center space-y-2">
            <p className="text-sm font-mono text-green-400">AUTENTICAÇÃO</p>
            <h1 className="text-3xl font-bold">Bem-vindo ao GateStack</h1>
            <p className="text-gray-400 text-sm">
              {mode === 'register' && 'Crie sua conta para começar'}
              {mode === 'login' && 'Entre para acessar o dashboard'}
              {mode === 'mfa' && 'Confirme seu código de autenticação'}
            </p>
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            {error && (
              <div className="flex items-center gap-2 p-4 rounded-lg bg-red-400/10 border border-red-400/30 text-red-300 text-sm">
                <AlertCircle className="h-4 w-4 flex-shrink-0" />
                {error}
              </div>
            )}

            {mode === 'mfa' ? (
              <>
                <div className="space-y-2">
                  <label className="text-sm font-medium text-gray-300">Código de Autenticação</label>
                  <input
                    type="text"
                    inputMode="numeric"
                    maxLength={6}
                    value={mfaCode}
                    onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ''))}
                    placeholder="000000"
                    className="w-full px-4 py-3 rounded-lg bg-dark-900 border border-white/10 text-white placeholder-gray-500 focus:outline-none focus:border-green-400"
                  />
                  <p className="text-xs text-gray-400">Digite o código do seu autenticador</p>
                </div>
              </>
            ) : (
              <>
                <div className="space-y-2">
                  <label className="text-sm font-medium text-gray-300">Email</label>
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="seu@email.com"
                    className="w-full px-4 py-3 rounded-lg bg-dark-900 border border-white/10 text-white placeholder-gray-500 focus:outline-none focus:border-green-400"
                  />
                </div>

                <div className="space-y-2">
                  <label className="text-sm font-medium text-gray-300">Senha</label>
                  <div className="relative">
                    <input
                      type={showPwd ? 'text' : 'password'}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="••••••••"
                      className="w-full px-4 py-3 rounded-lg bg-dark-900 border border-white/10 text-white placeholder-gray-500 focus:outline-none focus:border-green-400"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPwd(!showPwd)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-300"
                    >
                      {showPwd ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </button>
                  </div>
                </div>
              </>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 px-4 rounded-lg bg-green-400 text-dark-950 font-semibold hover:bg-green-300 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center justify-center gap-2"
            >
              {loading && <Loader2 className="h-4 w-4 animate-spin" />}
              {ctaText}
            </button>
          </form>

          {/* Toggle Mode */}
          {mode !== 'mfa' && (
            <div className="text-center text-sm">
              <span className="text-gray-400">
                {mode === 'register' ? 'Já tem conta? ' : 'Não tem conta? '}
              </span>
              <button
                type="button"
                onClick={() => {
                  setMode(mode === 'register' ? 'login' : 'register')
                  setError('')
                  setPassword('')
                }}
                className="text-green-400 hover:text-green-300 font-medium"
              >
                {mode === 'register' ? 'Entrar' : 'Criar conta'}
              </button>
            </div>
          )}

          {mode === 'mfa' && (
            <button
              type="button"
              onClick={() => {
                setMode('login')
                setMfaCode('')
                setError('')
              }}
              className="w-full py-2 text-sm text-gray-400 hover:text-gray-300"
            >
              Voltar ao login
            </button>
          )}
        </div>
      </div>
    </main>
  )
}
