import Link from 'next/link'
import { Compass, Flame, Globe2, Share2 } from 'lucide-react'
import { PublicCatalogPanel } from '@/components/features/PublicCatalogPanel'

export default function CatalogPage() {
  return (
    <div className="mx-auto max-w-7xl px-4 py-6 lg:px-6">
      <section className="mb-6 rounded-3xl border border-white/10 bg-dark-900/50 p-5 backdrop-blur">
        <p className="text-xs font-mono uppercase tracking-[0.2em] text-cyan-300">Feed do Catálogo</p>
        <h1 className="mt-2 text-3xl font-bold text-white">Descoberta social de pacotes</h1>
        <p className="mt-2 max-w-3xl text-sm text-gray-400">
          Explore versões públicas, tendências e downloads em uma experiência de feed contínuo.
        </p>
      </section>

      <section className="grid gap-5 xl:grid-cols-[260px_minmax(0,1fr)_280px]">
        <aside className="space-y-4">
          <div className="rounded-3xl border border-white/10 bg-dark-900/60 p-4">
            <p className="text-xs font-semibold uppercase tracking-widest text-gray-500">Explorar</p>
            <div className="mt-3 space-y-2 text-sm text-gray-200">
              <div className="flex items-center gap-2 rounded-2xl bg-white/5 px-3 py-2">
                <Compass className="h-4 w-4 text-cyan-300" />
                Novos pacotes
              </div>
              <div className="flex items-center gap-2 rounded-2xl bg-white/5 px-3 py-2">
                <Globe2 className="h-4 w-4 text-cyan-300" />
                Mais baixados
              </div>
              <div className="flex items-center gap-2 rounded-2xl bg-white/5 px-3 py-2">
                <Share2 className="h-4 w-4 text-cyan-300" />
                Recomendados
              </div>
            </div>
          </div>
          <div className="rounded-3xl border border-white/10 bg-dark-900/60 p-4 text-sm text-gray-200">
            <p className="text-xs font-semibold uppercase tracking-widest text-gray-500">Atalhos</p>
            <div className="mt-3 space-y-2">
              <Link href="/repository" className="block rounded-2xl bg-white/5 px-3 py-2 hover:bg-white/10">Abrir repositório</Link>
              <Link href="/dashboard" className="block rounded-2xl bg-white/5 px-3 py-2 hover:bg-white/10">Voltar ao feed</Link>
            </div>
          </div>
        </aside>

        <main>
          <PublicCatalogPanel />
        </main>

        <aside className="space-y-4">
          <div className="rounded-3xl border border-white/10 bg-dark-900/60 p-4">
            <div className="flex items-center gap-2">
              <Flame className="h-4 w-4 text-orange-300" />
              <p className="text-xs font-semibold uppercase tracking-widest text-gray-500">Tendências</p>
            </div>
            <div className="mt-3 space-y-2 text-sm text-gray-200">
              <div className="rounded-2xl bg-white/5 px-3 py-2">#public-release</div>
              <div className="rounded-2xl bg-white/5 px-3 py-2">#checksum-verified</div>
              <div className="rounded-2xl bg-white/5 px-3 py-2">#latest-stable</div>
            </div>
          </div>
          <div className="rounded-3xl border border-emerald-400/20 bg-emerald-400/10 p-4 text-sm text-emerald-100">
            <div className="inline-flex items-center gap-2">
              <Globe2 className="h-4 w-4" />
              Publicar para comunidade
            </div>
            <p className="mt-2 text-xs text-emerald-200/90">
              Pacotes com changelog claro e checksum público têm mais confiança e adoção.
            </p>
          </div>
        </aside>
      </section>
    </div>
  )
}
