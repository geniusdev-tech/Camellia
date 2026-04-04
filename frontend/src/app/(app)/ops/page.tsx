import Link from 'next/link'
import { AlertTriangle, Flame, ShieldCheck, Workflow } from 'lucide-react'
import { OpsPanel } from '@/components/features/OpsPanel'

export default function OpsPage() {
  return (
    <div className="mx-auto max-w-7xl px-4 py-6 lg:px-6">
      <section className="mb-6 rounded-3xl border border-white/10 bg-dark-900/50 p-5 backdrop-blur">
        <p className="text-xs font-mono uppercase tracking-[0.2em] text-cyan-300">Feed de Operações</p>
        <h1 className="mt-2 text-3xl font-bold text-white">Controle operacional em tempo real</h1>
        <p className="mt-2 max-w-3xl text-sm text-gray-400">
          Monitore jobs, enfileire workflows e acompanhe métricas como um painel social de atividade.
        </p>
      </section>

      <section className="grid gap-5 xl:grid-cols-[260px_minmax(0,1fr)_280px]">
        <aside className="space-y-4">
          <div className="rounded-3xl border border-white/10 bg-dark-900/60 p-4">
            <p className="text-xs font-semibold uppercase tracking-widest text-gray-500">Canais de operação</p>
            <div className="mt-3 space-y-2 text-sm text-gray-200">
              <div className="rounded-2xl bg-white/5 px-3 py-2">Monitor de fila</div>
              <div className="rounded-2xl bg-white/5 px-3 py-2">Alertas de deploy</div>
              <div className="rounded-2xl bg-white/5 px-3 py-2">Sala de incidentes</div>
            </div>
          </div>
          <div className="rounded-3xl border border-white/10 bg-dark-900/60 p-4 text-sm text-gray-200">
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
          <div className="rounded-3xl border border-white/10 bg-dark-900/60 p-4">
            <div className="flex items-center gap-2">
              <Flame className="h-4 w-4 text-orange-300" />
              <p className="text-xs font-semibold uppercase tracking-widest text-gray-500">Tendências</p>
            </div>
            <div className="mt-3 space-y-2 text-sm text-gray-200">
              <div className="rounded-2xl bg-white/5 px-3 py-2">#publish-async</div>
              <div className="rounded-2xl bg-white/5 px-3 py-2">#scan-queue</div>
              <div className="rounded-2xl bg-white/5 px-3 py-2">#route-metrics</div>
            </div>
          </div>
          <div className="rounded-3xl border border-amber-400/20 bg-amber-400/10 p-4 text-sm text-amber-100">
            <div className="inline-flex items-center gap-2">
              <AlertTriangle className="h-4 w-4" />
              Aviso operacional
            </div>
            <p className="mt-2 text-xs text-amber-200/90">Falhas repetidas de banco/queue devem gerar investigação de configuração antes de novo deploy.</p>
          </div>
          <Link href="/repository" className="flex items-center gap-2 rounded-2xl border border-white/10 bg-white/5 px-3 py-2 text-sm text-gray-200 hover:bg-white/10">
            <Workflow className="h-4 w-4 text-cyan-300" />
            Voltar para releases
          </Link>
        </aside>
      </section>
    </div>
  )
}
