import Link from 'next/link'
import { Flame, Library, Sparkles, Users } from 'lucide-react'
import { ReleaseControlCenter } from '@/components/features/ReleaseControlCenter'

export default function RepositoryPage() {
  return (
    <div className="mx-auto max-w-7xl px-4 py-6 lg:px-6">
      <section className="mb-6 rounded-3xl border border-white/10 bg-dark-900/50 p-5 backdrop-blur">
        <p className="text-xs font-mono uppercase tracking-[0.2em] text-cyan-300">Feed do Repositório</p>
        <h1 className="mt-2 text-3xl font-bold text-white">Timeline de releases</h1>
        <p className="mt-2 max-w-3xl text-sm text-gray-400">
          Navegue por versões, publique atualizações e acompanhe o estado do repositório como um feed de atividade.
        </p>
      </section>

      <section className="grid gap-5 xl:grid-cols-[260px_minmax(0,1fr)_280px]">
        <aside className="space-y-4">
          <div className="rounded-3xl border border-white/10 bg-dark-900/60 p-4">
            <p className="text-xs font-semibold uppercase tracking-widest text-gray-500">Comunidades ativas</p>
            <div className="mt-3 space-y-2">
              <div className="rounded-2xl bg-white/5 px-3 py-2 text-sm text-gray-200">Engenharia de Releases</div>
              <div className="rounded-2xl bg-white/5 px-3 py-2 text-sm text-gray-200">Revisão de Catálogo</div>
              <div className="rounded-2xl bg-white/5 px-3 py-2 text-sm text-gray-200">Time de Segurança</div>
            </div>
          </div>
          <div className="rounded-3xl border border-white/10 bg-dark-900/60 p-4">
            <p className="text-xs font-semibold uppercase tracking-widest text-gray-500">Atalhos</p>
            <div className="mt-3 space-y-2">
              <Link href="/dashboard" className="block rounded-2xl bg-white/5 px-3 py-2 text-sm text-gray-200 hover:bg-white/10">Voltar ao feed</Link>
              <Link href="/ops" className="block rounded-2xl bg-white/5 px-3 py-2 text-sm text-gray-200 hover:bg-white/10">Ver operações</Link>
            </div>
          </div>
        </aside>

        <main>
          <ReleaseControlCenter />
        </main>

        <aside className="space-y-4">
          <div className="rounded-3xl border border-white/10 bg-dark-900/60 p-4">
            <div className="flex items-center gap-2">
              <Flame className="h-4 w-4 text-orange-300" />
              <p className="text-xs font-semibold uppercase tracking-widest text-gray-500">Tendências</p>
            </div>
            <div className="mt-3 space-y-2 text-sm text-gray-200">
              <div className="rounded-2xl bg-white/5 px-3 py-2">#stable-publish</div>
              <div className="rounded-2xl bg-white/5 px-3 py-2">#rollback-safe</div>
              <div className="rounded-2xl bg-white/5 px-3 py-2">#supply-chain</div>
            </div>
          </div>
          <div className="rounded-3xl border border-white/10 bg-dark-900/60 p-4">
            <div className="flex items-center gap-2 text-sm text-white">
              <Library className="h-4 w-4 text-cyan-300" />
              Curadoria
            </div>
            <p className="mt-2 text-xs text-gray-500">Mantenha versões com changelog e metadados completos para melhorar a descoberta.</p>
          </div>
          <div className="rounded-3xl border border-emerald-400/20 bg-emerald-400/10 p-4 text-sm text-emerald-100">
            <div className="inline-flex items-center gap-2">
              <Sparkles className="h-4 w-4" />
              Publicar com confiança
            </div>
            <p className="mt-2 text-xs text-emerald-200/90">Use fluxos e validações antes de promover para produção.</p>
          </div>
          <Link href="/teams" className="flex items-center gap-2 rounded-2xl border border-white/10 bg-white/5 px-3 py-2 text-sm text-gray-200 hover:bg-white/10">
            <Users className="h-4 w-4 text-cyan-300" />
            Compartilhar com times
          </Link>
        </aside>
      </section>
    </div>
  )
}
