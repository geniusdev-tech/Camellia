import Link from 'next/link'
import { AlertTriangle, Flame, ShieldCheck, Workflow } from 'lucide-react'
import { OpsPanel } from '@/components/features/OpsPanel'

export default function OpsPage() {
  return (
    <div className="social-page">
      <section className="social-hero">
        <p className="text-xs font-mono uppercase tracking-[0.2em] text-cyan-300">Feed de Operações</p>
        <h1 className="mt-2 text-3xl font-bold text-white">Controle operacional em tempo real</h1>
        <p className="mt-2 max-w-3xl text-sm text-gray-400">
          Monitore jobs, enfileire workflows e acompanhe métricas como um painel social de atividade.
        </p>
      </section>

      <section className="social-layout">
        <aside className="space-y-4">
          <div className="social-side-card">
            <p className="text-xs font-semibold uppercase tracking-widest text-gray-500">Canais de operação</p>
            <div className="mt-3 space-y-2 text-sm text-gray-200">
              <div className="social-tile">Monitor de fila</div>
              <div className="social-tile">Alertas de deploy</div>
              <div className="social-tile">Sala de incidentes</div>
            </div>
          </div>
          <div className="social-side-card text-sm text-gray-200">
            <div className="inline-flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-cyan-300" />
              Meta de estabilidade
            </div>
            <p className="mt-2 text-xs text-gray-500">Mantenha jobs de scan/publish com retries controlados para evitar spam na fila.</p>
          </div>
        </aside>

        <main>
          <OpsPanel />
        </main>

        <aside className="space-y-4">
          <div className="social-side-card">
            <div className="flex items-center gap-2">
              <Flame className="h-4 w-4 text-orange-300" />
              <p className="text-xs font-semibold uppercase tracking-widest text-gray-500">Tendências</p>
            </div>
            <div className="mt-3 space-y-2 text-sm text-gray-200">
              <div className="social-tile">#publish-async</div>
              <div className="social-tile">#scan-queue</div>
              <div className="social-tile">#route-metrics</div>
            </div>
          </div>
          <div className="social-side-card border-amber-400/35 bg-amber-400/10 text-sm text-amber-100">
            <div className="inline-flex items-center gap-2">
              <AlertTriangle className="h-4 w-4" />
              Aviso operacional
            </div>
            <p className="mt-2 text-xs text-amber-200/90">Falhas repetidas de banco/queue devem gerar investigação de configuração antes de novo deploy.</p>
          </div>
          <Link href="/repository" className="social-link inline-flex items-center gap-2">
            <Workflow className="h-4 w-4 text-cyan-300" />
            Voltar para releases
          </Link>
        </aside>
      </section>
    </div>
  )
}
