'use client'

import { useCallback, useEffect, useMemo, useState, Suspense } from 'react'
import { useRouter, useSearchParams } from 'next/navigation'
import { Eye, EyeOff, Loader2, TerminalSquare, ArrowLeft, Github, ShieldAlert } from 'lucide-react'
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
    if (mode === 'register') return 'boot --create-user'
    if (mode === 'mfa') return 'verify --totp'
    return 'auth --login'
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
          const tokenFromMfa = response.accessToken || response.access_token
          if (response.success && tokenFromMfa) {
            setSession(
              {
                user_id: Number(response.user_id || userId),
                email: response.email || email,
                has_2fa: true,
                role: response.role || null,
              },
              tokenFromMfa,
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
          const tokenFromLogin = loginResponse.accessToken || loginResponse.access_token
          if (loginResponse.success && tokenFromLogin) {
            setSession(
              {
                user_id: Number(loginResponse.user_id || 0) || undefined,
                email: loginResponse.email || email,
                has_2fa: loginResponse.has_2fa || false,
                role: loginResponse.role || null,
              },
              tokenFromLogin,
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
    <main className="login-matrix-bg min-h-screen px-4 py-8 sm:py-12">
      <div className="login-matrix-overlay" />
      <div className="relative z-10 mx-auto grid w-full max-w-6xl gap-5 lg:grid-cols-[1.1fr_0.9fr]">
        <section className="login-terminal-panel">
          <div className="login-terminal-header">
            <span className="login-dot bg-red-400/80" />
            <span className="login-dot bg-amber-300/90" />
            <span className="login-dot bg-orange-400/85" />
            <p className="ml-3 text-[11px] text-orange-200/70">root@gatestack:~</p>
          </div>

          <div className="space-y-3 p-5 sm:p-7">
            <p className="text-[11px] uppercase tracking-[0.3em] text-orange-300/90">devsecops terminal</p>
            <h1 className="text-3xl font-bold text-orange-100 sm:text-4xl">GateStack Access Node</h1>
            <p className="max-w-xl text-sm text-orange-200/75">
              Ambiente de autenticação endurecido. Credenciais e tokens são validados com políticas de segurança em pipeline.
            </p>

            <div className="mt-5 space-y-2 rounded-2xl border border-orange-500/25 bg-black/30 p-4 font-mono text-xs text-orange-200/80">
              <p>&gt; sudo service gate-auth status</p>
              <p className="text-orange-300">active (running)</p>
              <p>&gt; sudo gate-check --policy hardened</p>
              <p className="text-orange-300">policy: ok | mfa: enforced | github-oauth: ready</p>
            </div>
          </div>
        </section>

        <section className="login-auth-panel">
          <div className="mb-4 flex items-center gap-2 text-orange-200">
            <TerminalSquare className="h-4 w-4" />
            <p className="text-xs font-mono uppercase tracking-[0.18em]">{mode === 'mfa' ? 'MFA Challenge' : 'Secure Login'}</p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            {error && (
              <div className="flex items-start gap-2 rounded-xl border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-sm text-rose-200">
                <ShieldAlert className="mt-0.5 h-4 w-4" />
                <span>{error}</span>
              </div>
            )}

            {mode === 'mfa' ? (
              <div className="space-y-2">
                <label className="text-xs uppercase tracking-[0.18em] text-orange-300/80">totp code</label>
                <input
                  type="text"
                  inputMode="numeric"
                  maxLength={6}
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ''))}
                  placeholder="000000"
                  className="login-input text-center font-mono text-2xl tracking-[0.45em]"
                  autoFocus
                />
              </div>
            ) : (
              <>
                <div className="space-y-2">
                  <label className="text-xs uppercase tracking-[0.18em] text-orange-300/80">email</label>
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="dev@company.com"
                    className="login-input"
                    autoFocus
                  />
                </div>

                <div className="space-y-2">
                  <label className="text-xs uppercase tracking-[0.18em] text-orange-300/80">password</label>
                  <div className="relative">
                    <input
                      type={showPwd ? 'text' : 'password'}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      placeholder="••••••••"
                      className="login-input pr-12"
                    />
                    <button type="button" onClick={() => setShowPwd((current) => !current)} className="absolute right-3 top-1/2 -translate-y-1/2 text-orange-300/70 hover:text-orange-200">
                      {showPwd ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </button>
                  </div>
                </div>
              </>
            )}

            <button type="submit" disabled={loading} className="login-submit-btn">
              {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
              {ctaText}
            </button>

            {mode === 'login' ? (
              <button type="button" onClick={handleGithubLogin} disabled={loading} className="login-github-btn">
                <Github className="h-4 w-4" />
                oauth --provider github
              </button>
            ) : null}
          </form>

          {mode !== 'mfa' ? (
            <div className="mt-4 text-sm text-orange-200/75">
              <span>{mode === 'register' ? 'já possui acesso? ' : 'novo no ambiente? '}</span>
              <button
                type="button"
                onClick={() => {
                  setMode(mode === 'register' ? 'login' : 'register')
                  setError('')
                  setPassword('')
                }}
                className="font-semibold text-orange-300 hover:text-orange-200"
              >
                {mode === 'register' ? 'auth --login' : 'boot --create-user'}
              </button>
            </div>
          ) : (
            <button
              type="button"
              onClick={() => {
                setMode('login')
                setMfaCode('')
                setError('')
              }}
              className="mt-4 inline-flex items-center gap-2 text-sm text-orange-200/70 hover:text-orange-200"
            >
              <ArrowLeft className="h-3.5 w-3.5" />
              return --login
            </button>
          )}
        </section>
      </div>
    </main>
  )
}

export default function LoginPage() {
  return (
    <Suspense fallback={<div className="min-h-screen flex items-center justify-center"><Loader2 className="h-8 w-8 animate-spin text-orange-300" /></div>}>
      <LoginForm />
    </Suspense>
  )
}
