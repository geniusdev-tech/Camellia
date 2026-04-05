'use client'
import { useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { useAuthStore } from '@/store/auth'
import { Shield, Zap, Lock, BarChart3, GitBranch, Server, ArrowRight, Terminal } from 'lucide-react'

const features = [
  {
    icon: Lock,
    title: 'Acesso Granular',
    desc: 'Políticas baseadas em regras com aprovação automática e audit trail criptografado.',
    color: 'green',
  },
  {
    icon: Zap,
    title: 'Detecção em Tempo Real',
    desc: 'ML em produção para análise comportamental, alertas inteligentes e resposta automatizada.',
    color: 'cyan',
  },
  {
    icon: BarChart3,
    title: 'Compliance Automático',
    desc: 'SOC2, ISO27001, LGPD, GDPR — mapeamento, relatórios e coleta de evidências automática.',
    color: 'green',
  },
]

const stack = [
  { name: 'NestJS', category: 'Backend', level: 92, icon: Server },
  { name: 'React', category: 'Frontend', level: 89, icon: Terminal },
  { name: 'PostgreSQL', category: 'Database', level: 88, icon: GitBranch },
  { name: 'Kubernetes', category: 'Orchest.', level: 85, icon: Server },
  { name: 'TypeScript', category: 'Tipado', level: 87, icon: Terminal },
  { name: 'Docker', category: 'Containers', level: 91, icon: GitBranch },
]

export default function RootPage() {
  const router = useRouter()
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)

  useEffect(() => {
    if (isAuthenticated === true) {
      router.replace('/dashboard')
    }
  }, [isAuthenticated, router])

  if (isAuthenticated === null || isAuthenticated === undefined) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="flex flex-col items-center gap-6">
          <div className="w-14 h-14 border-2 border-green-400/30 border-t-green-400 rounded-full animate-spin" />
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen">
      {/* ─── Hero ─────────────────────────────── */}
      <section className="relative mx-auto max-w-6xl px-5 sm:px-6 pt-24 sm:pt-36 pb-20">
        <div className="relative mx-auto max-w-3xl text-center space-y-8">
          <div className="animate-fade-up">
            <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full glass-subtle text-xs font-mono text-cyan-400 tracking-widest">
              <span className="inline-block h-1.5 w-1.5 rounded-full bg-green-400 animate-pulse" />
              SISTEMA OPERACIONAL
            </div>
          </div>

          <h1 className="animate-fade-up delay-100 text-5xl sm:text-7xl font-black tracking-tight leading-[1.05]">
            Conformidade
            <br />
            <span className="bg-gradient-to-r from-green-400 via-emerald-400 to-cyan-400 bg-clip-text text-transparent">
              sem caos
            </span>
          </h1>

          <p className="animate-fade-up delay-200 text-lg sm:text-xl text-gray-400 leading-relaxed max-w-2xl mx-auto font-light">
            Acesso visível. Políticas em tempo real. Compliance automático.
            <br className="hidden sm:block" />
            Inteligência contínua para equipes DevOps enterprise.
          </p>

          <div className="animate-fade-up delay-300 flex flex-col sm:flex-row gap-4 justify-center pt-2">
            <a
              href="/login"
              className="group px-8 py-3.5 bg-gradient-to-r from-green-400 to-emerald-500 text-dark-950 font-semibold rounded-xl hover:shadow-lg hover:shadow-green-400/30 transition-all active:scale-[0.97] flex items-center justify-center gap-2"
            >
              Iniciar Acesso
              <ArrowRight className="h-4 w-4 group-hover:translate-x-0.5 transition-transform" />
            </a>
            <a
              href="/#sobre"
              className="px-8 py-3.5 glass-subtle text-gray-300 font-medium rounded-xl hover:text-white hover:border-cyan-400/25 transition-all flex items-center justify-center gap-2"
            >
              <Terminal className="h-4 w-4 text-cyan-400" />
              Saiba Mais
            </a>
          </div>
        </div>
      </section>

      {/* ─── Features ─────────────────────────── */}
      <section id="sobre" className="mx-auto max-w-6xl px-5 sm:px-6 py-20 sm:py-28">
        <div className="text-center mb-16 animate-fade-up">
          <p className="text-xs font-mono text-cyan-400 tracking-[0.3em] uppercase mb-3">Capacidades</p>
          <h2 className="text-3xl sm:text-4xl font-bold">
            Segurança que{' '}
            <span className="bg-gradient-to-r from-green-400 to-cyan-400 bg-clip-text text-transparent">
              escala
            </span>
          </h2>
        </div>

        <div className="grid md:grid-cols-3 gap-6">
          {features.map((feat, idx) => (
            <div
              key={feat.title}
              className="glass rounded-2xl p-7 transition-all duration-300 hover:scale-[1.02] hover:border-cyan-400/25 animate-fade-up group"
              style={{ animationDelay: `${(idx + 1) * 100}ms` }}
            >
              <div className={`flex h-12 w-12 items-center justify-center rounded-xl mb-5 transition-all ${
                feat.color === 'cyan'
                  ? 'bg-cyan-400/10 border border-cyan-400/20 group-hover:bg-cyan-400/15 group-hover:cyber-glow-cyan'
                  : 'bg-green-400/10 border border-green-400/20 group-hover:bg-green-400/15 group-hover:cyber-glow'
              }`}>
                <feat.icon className={`h-6 w-6 ${feat.color === 'cyan' ? 'text-cyan-400' : 'text-green-400'}`} />
              </div>
              <h3 className="text-lg font-semibold text-white mb-2">{feat.title}</h3>
              <p className="text-sm text-gray-400 leading-relaxed">{feat.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ─── Stack ────────────────────────────── */}
      <section id="stack" className="mx-auto max-w-6xl px-5 sm:px-6 py-20 sm:py-28">
        <div className="text-center mb-16 animate-fade-up">
          <p className="text-xs font-mono text-green-400 tracking-[0.3em] uppercase mb-3">Tecnologias</p>
          <h2 className="text-3xl sm:text-4xl font-bold">
            Stack em{' '}
            <span className="bg-gradient-to-r from-green-400 to-cyan-400 bg-clip-text text-transparent">
              produção
            </span>
          </h2>
          <p className="text-gray-500 text-base max-w-lg mx-auto mt-3">
            O melhor do ecossistema para sistemas que precisam escalar.
          </p>
        </div>

        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {stack.map((tech, idx) => (
            <div
              key={tech.name}
              className="glass rounded-xl p-5 transition-all duration-300 hover:border-cyan-400/20 hover:scale-[1.01] animate-fade-up group"
              style={{ animationDelay: `${(idx + 1) * 80}ms` }}
            >
              <div className="flex justify-between items-start mb-4">
                <div className="flex items-center gap-3">
                  <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-white/5 border border-white/5 group-hover:border-green-400/20 transition-colors">
                    <tech.icon className="h-4 w-4 text-gray-400 group-hover:text-green-400 transition-colors" />
                  </div>
                  <div>
                    <h3 className="font-mono font-semibold text-white text-sm">{tech.name}</h3>
                    <p className="text-xs text-gray-500">{tech.category}</p>
                  </div>
                </div>
                <span className={`font-mono text-sm font-bold ${tech.level >= 90 ? 'text-green-400' : 'text-cyan-400'}`}>
                  {tech.level}%
                </span>
              </div>
              <div className="w-full bg-white/5 rounded-full h-1 overflow-hidden">
                <div
                  className={`h-1 rounded-full transition-all duration-700 ${
                    tech.level >= 90
                      ? 'bg-gradient-to-r from-green-400/80 to-green-300'
                      : 'bg-gradient-to-r from-cyan-400/80 to-cyan-300'
                  }`}
                  style={{ width: `${tech.level}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* ─── CTA ──────────────────────────────── */}
      <section className="mx-auto max-w-6xl px-5 sm:px-6 py-20 sm:py-28">
        <div className="glass rounded-3xl p-10 sm:p-16 text-center animate-border-glow">
          <div className="space-y-6 max-w-2xl mx-auto">
            <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-green-400/8 border border-green-400/20 text-xs font-mono text-green-400 tracking-widest">
              <Shield className="h-3 w-3" />
              READY
            </div>
            <h2 className="text-3xl sm:text-4xl font-bold">
              Conformidade
              <br />
              <span className="bg-gradient-to-r from-cyan-400 to-green-400 bg-clip-text text-transparent">
                que não desacelera
              </span>
            </h2>
            <p className="text-gray-400 text-base sm:text-lg">
              Acesso em minutos. Políticas em tempo real. Compliance automático.
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center pt-4">
              <a
                href="/login"
                className="group px-8 py-3.5 bg-gradient-to-r from-green-400 to-emerald-500 text-dark-950 font-semibold rounded-xl hover:shadow-lg hover:shadow-green-400/30 transition-all active:scale-[0.97] flex items-center justify-center gap-2"
              >
                Teste Gratuito
                <ArrowRight className="h-4 w-4 group-hover:translate-x-0.5 transition-transform" />
              </a>
              <a
                href="mailto:contato@gatestack.dev"
                className="px-8 py-3.5 glass-subtle text-gray-300 font-medium rounded-xl hover:text-white transition-all flex items-center justify-center"
              >
                Agendar Demo
              </a>
            </div>
          </div>
        </div>
      </section>

      {/* Footer spacer */}
      <div className="h-12" />
    </div>
  )
}
