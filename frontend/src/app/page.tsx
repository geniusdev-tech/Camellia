'use client'

import { useEffect } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { ArrowRight, Github, ShieldCheck } from 'lucide-react'
import { useAuthStore } from '@/store/auth'

export default function RootPage() {
  const router = useRouter()
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated)

  useEffect(() => {
    if (isAuthenticated) router.replace('/dashboard')
  }, [isAuthenticated, router])

  if (isAuthenticated) return null

  return (
    <main className="login-matrix-bg min-h-screen px-4 py-10">
      <div className="login-matrix-overlay" />
      <section className="relative z-10 mx-auto max-w-4xl rounded-3xl border border-orange-500/25 bg-black/45 p-6 sm:p-10">
        <p className="text-xs font-mono uppercase tracking-[0.28em] text-orange-300/90">gate access gateway</p>
        <h1 className="mt-3 text-4xl font-bold text-orange-100 sm:text-5xl">Frontend GitHub-Only</h1>
        <p className="mt-4 max-w-2xl text-sm text-orange-200/80 sm:text-base">
          Todas as rotas do app exibem somente dados vindos da integração GitHub. Faça login para abrir o dashboard social.
        </p>

        <div className="mt-7 flex flex-wrap gap-3">
          <Link href="/login" className="login-submit-btn w-auto px-5">
            Entrar agora <ArrowRight className="h-4 w-4" />
          </Link>
          <a href="https://github.com" target="_blank" rel="noreferrer" className="login-github-btn w-auto px-5">
            <Github className="h-4 w-4" />
            GitHub
          </a>
        </div>

        <div className="mt-8 rounded-2xl border border-orange-500/20 bg-orange-500/8 p-4">
          <p className="inline-flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.18em] text-orange-300">
            <ShieldCheck className="h-3.5 w-3.5" />
            Data policy
          </p>
          <p className="mt-2 text-sm text-orange-200/80">
            Sem dados mockados de catálogo, operações ou times fora do escopo da API GitHub.
          </p>
        </div>
      </section>
    </main>
  )
}
