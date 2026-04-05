'use client'

import { useCallback, useEffect, useMemo, useState, Suspense } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { Eye, EyeOff, AlertCircle, Loader2, Shield, ArrowLeft, Github } from 'lucide-react'
import { authAPI, githubAPI } from '@/lib/api'
import { getApiBase } from '@/lib/tauri'
import { useAuthStore } from '@/store/auth'

type Mode = 'login' | 'register' | 'mfa'

function LoginForm() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const setSession = useAuthStore((state) => state.setSession)
  const logout = useAuthStore((state) => state.logout)

  const [mode, setMode] = useState<Mode>('login')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [mfaCode, setMfaCode] = useState('')
  const [userId, setUserId] = useState<number | string | null>(null)
  const [showPwd, setShowPwd] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  // GitHub token capture
  useEffect(() => {
    const token = searchParams.get('token')
    const oauthSuccess = searchParams.get('oauth') === 'success'
    const oauthError = searchParams.get('error')
    if (oauthError) {
      logout()
      setError('Falha no login com GitHub. Tente novamente.')
      setLoading(false)
      return
    }

    if (oauthSuccess) {
      setLoading(true)
      authAPI.githubSession()
        .then((sessionRes) => {
          useAuthStore.getState().updateAccessToken(sessionRes.accessToken)
          return authAPI.me().then((meRes) => ({ meRes, accessToken: sessionRes.accessToken }))
        })
        .then(({ meRes, accessToken }) => {
          if (meRes.success && meRes.user) {
            setSession(
              {
                user_id: meRes.user.user_id || meRes.user.id,
                email: meRes.user.email,
                name: meRes.user.name,
                avatarUrl: meRes.user.avatarUrl,
                github_id: meRes.user.githubId || meRes.user.github_id,
                has_2fa: meRes.user.has_2fa || false,
                role: meRes.user.role || null,
              },
              accessToken,
            )
            // Best-effort sync so repositories are available immediately after OAuth login.
            void githubAPI.sync().catch(() => undefined)
            router.replace('/dashboard')
            return
          }
          logout()
          setError('Falha ao obter perfil do GitHub')
          setLoading(false)
        })
        .catch(() => {
          logout()
          setError('Erro ao validar sessão do GitHub')
          setLoading(false)
        })
      return
    }

    if (token) {
      setLoading(true)
      // Save it temporarily so fetchAPI has it for the /me request
      useAuthStore.getState().updateAccessToken(token)
      authAPI.me()
        .then((res) => {
          if (res.success && res.user) {
            setSession(
              {
                user_id: res.user.user_id || res.user.id,
                email: res.user.email,
                name: res.user.name,
                avatarUrl: res.user.avatarUrl,
                github_id: res.user.githubId || res.user.github_id,
                has_2fa: res.user.has_2fa || false,
                role: res.user.role || null,
              },
              token,
            )
            router.replace('/dashboard')
          } else {
            logout()
            setError('Falha ao obter perfil do GitHub')
            setLoading(false)
          }
        })
        .catch(() => {
          logout()
          setError('Erro ao validar token do GitHub')
          setLoading(false)
        })
    }
  }, [searchParams, router, setSession, logout])

  const handleGithubLogin = async () => {
    setLoading(true)
    const base = await getApiBase()
    window.location.href = `${base}/api/auth/github`
  }

  const ctaText = useMemo(() => {
    if (mode === 'register') return 'Criar Conta'
    if (mode === 'mfa') return 'Confirmar Código'
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
    <main className="min-h-screen flex items-center justify-center px-4 py-12">
      <div className="w-full max-w-md animate-fade-up">
        {/* Glass Card */}
        <div className="glass rounded-3xl p-8 sm:p-10 space-y-8 animate-border-glow">
          {/* Logo & Header */}
          <div className="text-center space-y-3">
            <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-br from-green-400/20 to-cyan-400/20 border border-green-400/20 cyber-glow">
              <Shield className="h-7 w-7 text-green-400" />
            </div>
            <div>
              <p className="text-xs font-mono text-cyan-400 tracking-[0.3em] uppercase">
                {mode === 'register' ? 'novo acesso' : mode === 'mfa' ? 'verificação' : 'autenticação'}
              </p>
              <h1 className="text-2xl sm:text-3xl font-bold mt-1">
                <span className="bg-gradient-to-r from-green-400 to-cyan-400 bg-clip-text text-transparent">
                  GateStack
                </span>
              </h1>
              <p className="text-gray-500 text-sm mt-1">
                {mode === 'register' && 'Crie sua conta para começar'}
                {mode === 'login' && 'Entre para acessar o dashboard'}
                {mode === 'mfa' && 'Confirme seu código de autenticação'}
              </p>
            </div>
          </div>

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-5">
            {error && (
              <div className="flex items-center gap-2.5 p-3.5 rounded-xl text-sm glass-subtle" style={{ borderColor: 'rgba(239, 68, 68, 0.25)', background: 'rgba(239, 68, 68, 0.06)' }}>
                <AlertCircle className="h-4 w-4 flex-shrink-0 text-red-400" />
                <span className="text-red-300">{error}</span>
              </div>
            )}

            {mode === 'mfa' ? (
              <div className="space-y-2">
                <label className="text-xs font-medium text-gray-400 uppercase tracking-wider">Código MFA</label>
                <input
                  type="text"
                  inputMode="numeric"
                  maxLength={6}
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ''))}
                  placeholder="000000"
                  className="h-input text-center text-2xl font-mono tracking-[0.5em]"
                  autoFocus
                />
                <p className="text-xs text-gray-500 text-center">Digite o código do seu autenticador</p>
              </div>
            ) : (
              <>
                <div className="space-y-2">
                  <label className="text-xs font-medium text-gray-400 uppercase tracking-wider">Email</label>
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="seu@email.com"
                    className="h-input"
                    autoFocus
                  />
                </div>

                <div className="space-y-2">
                  <label className="text-xs font-medium text-gray-400 uppercase tracking-wider">Senha</label>
                  <div className="relative">
                    <input
                      type={showPwd ? 'text' : 'password'}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="••••••••"
                      className="h-input pr-12"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPwd(!showPwd)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 p-1.5 rounded-lg text-gray-500 hover:text-gray-300 hover:bg-white/5 transition-all"
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
              className="w-full py-3.5 px-4 rounded-xl font-semibold text-sm transition-all duration-200 flex items-center justify-center gap-2 disabled:opacity-40 disabled:cursor-not-allowed bg-gradient-to-r from-green-400 to-emerald-500 text-dark-950 hover:shadow-lg hover:shadow-green-400/25 active:scale-[0.98]"
            >
              {loading && <Loader2 className="h-4 w-4 animate-spin" />}
              {ctaText}
            </button>
            
            {mode === 'login' && (
              <>
                <div className="relative flex items-center py-2">
                  <div className="flex-grow border-t border-white/10"></div>
                  <span className="flex-shrink-0 mx-4 text-xs font-mono text-gray-500 uppercase tracking-widest">ou</span>
                  <div className="flex-grow border-t border-white/10"></div>
                </div>

                <button
                  type="button"
                  onClick={handleGithubLogin}
                  disabled={loading}
                  className="w-full flex items-center justify-center gap-3 py-3 px-4 rounded-xl font-semibold text-sm transition-all text-white bg-[#24292e] border border-white/10 hover:bg-[#2f363d] focus:ring-2 focus:ring-cyan-500/50 disabled:opacity-40"
                >
                  <Github className="h-5 w-5" />
                  Continuar com GitHub
                </button>
              </>
            )}
          </form>

          {/* Toggle Mode */}
          {mode !== 'mfa' && (
            <div className="text-center text-sm">
              <span className="text-gray-500">
                {mode === 'register' ? 'Já tem conta? ' : 'Não tem conta? '}
              </span>
              <button
                type="button"
                onClick={() => {
                  setMode(mode === 'register' ? 'login' : 'register')
                  setError('')
                  setPassword('')
                }}
                className="text-cyan-400 hover:text-cyan-300 font-medium transition-colors"
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
              className="w-full flex items-center justify-center gap-2 py-2 text-sm text-gray-500 hover:text-gray-300 transition-colors"
            >
              <ArrowLeft className="h-3.5 w-3.5" />
              Voltar ao login
            </button>
          )}
        </div>

        {/* Footer */}
        <p className="text-center text-xs text-gray-600 mt-6 font-mono">
          gatestack v3.0 · conformidade sem caos
        </p>
      </div>
    </main>
  )
}

export default function LoginPage() {
  return (
    <Suspense fallback={<div className="min-h-screen flex items-center justify-center"><Loader2 className="h-8 w-8 animate-spin text-cyan-400" /></div>}>
      <LoginForm />
    </Suspense>
  )
}
