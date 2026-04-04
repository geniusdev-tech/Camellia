'use client'
import { useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { useAuthStore } from '@/store/auth'

export default function RootPage() {
  const router = useRouter()
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)

  useEffect(() => {
    if (isAuthenticated === true) {
      router.replace('/dashboard')
    } else if (isAuthenticated === false) {
      // Stay on landing page
    }
  }, [isAuthenticated, router])

  if (isAuthenticated === null || isAuthenticated === undefined) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="flex flex-col items-center gap-6">
          <div className="w-16 h-16 border-4 border-green-400/30 border-t-green-400 rounded-full animate-spin" />
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen">
      {/* Hero Section */}
      <section className="relative mx-auto max-w-7xl px-6 py-24 sm:py-32">
        {/* Background decorative elements */}
        <div className="absolute inset-0 overflow-hidden pointer-events-none">
          <div className="absolute top-20 left-1/4 w-96 h-96 bg-cyan-400/10 rounded-full blur-3xl opacity-20" />
          <div className="absolute bottom-20 right-1/4 w-96 h-96 bg-green-400/10 rounded-full blur-3xl opacity-20" />
        </div>

        <div className="relative mx-auto max-w-2xl text-center space-y-8">
          <div className="space-y-4">
            <div className="inline-block px-4 py-1.5 border border-cyan-400/50 rounded-full text-xs font-mono text-cyan-400 tracking-widest">
              $ GATESTACK_INIT /secure
            </div>
            <h1 className="text-5xl sm:text-6xl font-black tracking-tight">
              Conformidade
              <br />
              <span className="bg-gradient-to-r from-green-400 to-cyan-400 bg-clip-text text-transparent">sem caos</span>
            </h1>
          </div>
          
          <p className="text-xl text-gray-400 leading-relaxed max-w-xl mx-auto font-light">
            Acesso visível. Políticas que funcionam em tempo real. Compliance automático. Inteligencia contínua para equipes DevOps enterprise.
          </p>
          
          <div className="flex flex-col sm:flex-row gap-4 justify-center pt-4">
            <a 
              href="/login" 
              className="px-8 py-3 bg-gradient-to-r from-green-400 to-green-500 text-dark-950 font-semibold rounded hover:shadow-lg hover:shadow-green-400/50 transition-all active:scale-95"
            >
              → iniciar_acesso
            </a>
            <a 
              href="/#sobre" 
              className="px-8 py-3 border border-cyan-400/50 text-cyan-400 font-mono rounded hover:bg-cyan-400/10 hover:shadow-lg hover:shadow-cyan-400/30 transition-all"
            >
              $ saiba_mais
            </a>
          </div>
        </div>
      </section>

      {/* Section 01 - Access Control */}
      <section id="sobre" className="mx-auto max-w-7xl px-6 py-24 border-t border-white/5">
        <div className="grid md:grid-cols-2 gap-16 items-center">
          <div>
            <div className="text-xs font-mono text-cyan-400 mb-4 tracking-widest">$ ls -la / 01_ACESSO</div>
            <h2 className="text-4xl font-bold mb-6 leading-tight">
              Acesso sem fricção
            </h2>
            <p className="text-gray-400 text-lg leading-relaxed mb-8">
              Policies e permissões que fazem sentido para como seu time realmente trabalha. Sem complicações. Sem espera.
            </p>
            <ul className="space-y-4 text-gray-300 font-mono text-sm">
              <li className="flex gap-3 items-start">
                <span className="text-green-400 flex-shrink-0 mt-0.5">{">>"}</span>
                <span>Acesso granular baseado em regras</span>
              </li>
              <li className="flex gap-3 items-start">
                <span className="text-cyan-400 flex-shrink-0 mt-0.5">{">>"}</span>
                <span>Aprovação automática e rápida</span>
              </li>
              <li className="flex gap-3 items-start">
                <span className="text-green-400 flex-shrink-0 mt-0.5">{">>"}</span>
                <span>Audit trail com assinatura criptográfica</span>
              </li>
            </ul>
          </div>
          <div className="bg-dark-900/50 border border-cyan-400/30 rounded-lg p-8 cyber-glow-cyan relative">
            <div className="absolute top-2 left-2 text-[0.6rem] font-mono text-cyan-400 opacity-50"># access_control.log</div>
            <div className="h-64 bg-gradient-to-br from-cyan-400/10 via-green-400/5 to-transparent rounded flex items-center justify-center text-gray-500">
              [Visualização de Acesso]
            </div>
          </div>
        </div>
      </section>

      {/* Section 02 - Intelligence */}
      <section className="mx-auto max-w-7xl px-6 py-24 border-t border-white/5">
        <div className="grid md:grid-cols-2 gap-16 items-center">
          <div className="bg-dark-900/50 border border-green-400/30 rounded-lg p-8 cyber-glow order-2 md:order-1 relative">
            <div className="absolute top-2 left-2 text-[0.6rem] font-mono text-green-400 opacity-50"># threat_detection.py</div>
            <div className="h-64 bg-gradient-to-br from-green-400/10 via-cyan-400/5 to-transparent rounded flex items-center justify-center text-gray-500">
              [Inteligência em Tempo Real]
            </div>
          </div>
          <div className="order-1 md:order-2">
            <div className="text-xs font-mono text-green-400 mb-4 tracking-widest">$ ./bin/intelligence 02_THREATS</div>
            <h2 className="text-4xl font-bold mb-6 leading-tight">
              Ameaças em tempo real
            </h2>
            <p className="text-gray-400 text-lg leading-relaxed mb-8">
              Detecção contínua de anomalias, comportamentos suspeitos e violações de políticas. Machine learning em produção.
            </p>
            <ul className="space-y-4 text-gray-300 font-mono text-sm">
              <li className="flex gap-3 items-start">
                <span className="text-green-400 flex-shrink-0 mt-0.5">{">>"}</span>
                <span>Análise de comportamento com ML</span>
              </li>
              <li className="flex gap-3 items-start">
                <span className="text-cyan-400 flex-shrink-0 mt-0.5">{">>"}</span>
                <span>Alertas inteligentes, sem ruído</span>
              </li>
              <li className="flex gap-3 items-start">
                <span className="text-green-400 flex-shrink-0 mt-0.5">{">>"}</span>
                <span>Resposta automática a incidentes</span>
              </li>
            </ul>
          </div>
        </div>
      </section>

      {/* Section 03 - Compliance */}
      <section className="mx-auto max-w-7xl px-6 py-24 border-t border-white/5">
        <div className="grid md:grid-cols-2 gap-16 items-center">
          <div>
            <div className="text-xs font-mono text-cyan-400 mb-4 tracking-widest">$ ./bin/compliance 03_FRAMEWORKS</div>
            <h2 className="text-4xl font-bold mb-6 leading-tight">
              Compliance que escala
            </h2>
            <p className="text-gray-400 text-lg leading-relaxed mb-8">
              SOC2, ISO27001, LGPD, GDPR — menos trabalho manual, mais confiança. Sua auditoria automática.
            </p>
            <ul className="space-y-4 text-gray-300 font-mono text-sm">
              <li className="flex gap-3 items-start">
                <span className="text-cyan-400 flex-shrink-0 mt-0.5">{">>"}</span>
                <span>Mapeamento automático de frameworks</span>
              </li>
              <li className="flex gap-3 items-start">
                <span className="text-green-400 flex-shrink-0 mt-0.5">{">>"}</span>
                <span>Relatórios contínuos e auditáveis</span>
              </li>
              <li className="flex gap-3 items-start">
                <span className="text-cyan-400 flex-shrink-0 mt-0.5">{">>"}</span>
                <span>Coleta de evidências automática</span>
              </li>
            </ul>
          </div>
          <div className="bg-dark-900/50 border border-cyan-400/30 rounded-lg p-8 cyber-glow-cyan relative">
            <div className="absolute top-2 left-2 text-[0.6rem] font-mono text-cyan-400 opacity-50"># compliance_report.json</div>
            <div className="h-64 bg-gradient-to-br from-cyan-400/10 via-green-400/5 to-transparent rounded flex items-center justify-center text-gray-500">
              [Relatório de Conformidade]
            </div>
          </div>
        </div>
      </section>

      {/* Section Stack */}
      <section id="stack" className="mx-auto max-w-7xl px-6 py-24 border-t border-white/5">
        <div className="text-center mb-16">
          <div className="text-xs font-mono text-cyan-400 mb-4 tracking-widest">$ cat stack.yml</div>
          <h2 className="text-4xl font-bold mb-4">
            Tecnologias <span className="bg-gradient-to-r from-green-400 to-cyan-400 bg-clip-text text-transparent">em produção</span>
          </h2>
          <p className="text-gray-400 text-lg max-w-xl mx-auto">
            Go, React, PostgreSQL. O melhor do ecossistema para sistemas que precisam escalar.
          </p>
        </div>

        <div className="grid md:grid-cols-3 gap-8">
          {[
            { name: 'Go', category: 'Backend', proficiency: 92 },
            { name: 'React', category: 'Frontend', proficiency: 89 },
            { name: 'PostgreSQL', category: 'Database', proficiency: 88 },
            { name: 'Kubernetes', category: 'Orchest.', proficiency: 85 },
            { name: 'TypeScript', category: 'Tipado', proficiency: 87 },
            { name: 'Docker', category: 'Containers', proficiency: 91 },
          ].map((tech) => (
            <div key={tech.name} className="bg-dark-900/40 border border-green-400/30 rounded-lg p-6 hover:border-cyan-400/50 transition-all cyber-glow">
              <div className="flex justify-between items-start mb-4">
                <div>
                  <h3 className="font-mono font-semibold text-white">{tech.name}</h3>
                  <p className="text-xs text-gray-500 tracking-wide">{tech.category}</p>
                </div>
                <span className={`${tech.proficiency >= 90 ? 'text-green-400' : 'text-cyan-400'} font-mono font-bold`}>{tech.proficiency}%</span>
              </div>
              <div className="w-full bg-dark-800 rounded-full h-1.5 border border-white/5 overflow-hidden">
                <div 
                  className={`h-1.5 rounded-full transition-all duration-500 ${
                    tech.proficiency >= 90
                      ? 'bg-gradient-to-r from-green-400 to-green-300 shadow-lg shadow-green-400/50'
                      : 'bg-gradient-to-r from-cyan-400 to-cyan-300 shadow-lg shadow-cyan-400/30'
                  }`}
                  style={{ width: `${tech.proficiency}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* CTA Section */}
      <section className="mx-auto max-w-7xl px-6 py-24 border-t border-white/5 relative">
        <div className="text-center space-y-8">
          <div className="space-y-4">
            <div className="inline-block px-4 py-1.5 border border-green-400/50 rounded-full text-xs font-mono text-green-400 tracking-widest">
              $ gatestack --init
            </div>
            <h2 className="text-4xl font-bold">
              Conformidade
              <br />
              <span className="bg-gradient-to-r from-cyan-400 to-green-400 bg-clip-text text-transparent">que não desacelera</span>
            </h2>
            <p className="text-gray-400 text-lg max-w-2xl mx-auto">
              Acesso em minutos. Políticas em tempo real. Compliance automático. Sua equipe DevOps vai respirar fundo.
            </p>
          </div>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <a 
              href="/login" 
              className="px-8 py-3 bg-gradient-to-r from-green-400 to-green-500 text-dark-950 font-semibold rounded hover:shadow-lg hover:shadow-green-400/50 transition-all active:scale-95"
            >
              → iniciar_teste_gratuito
            </a>
            <a 
              href="mailto:contato@gatestack.dev" 
              className="px-8 py-3 border border-cyan-400/50 text-cyan-400 font-mono rounded hover:bg-cyan-400/10 hover:shadow-lg hover:shadow-cyan-400/30 transition-all"
            >
              $ agendar_demo
            </a>
          </div>
        </div>
      </section>
    </div>
  )
}
