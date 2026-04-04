import Link from 'next/link'
import { Compass, Flame, Globe2, Share2 } from 'lucide-react'
import { PublicCatalogPanel } from '@/components/features/PublicCatalogPanel'

export default function CatalogPage() {
  return (
    <div className="social-page">
      <section className="social-hero">
        <p className="text-xs font-mono uppercase tracking-[0.2em] text-cyan-300">Feed do Catálogo</p>
        <h1 className="mt-2 text-3xl font-bold text-white">Descoberta social de pacotes</h1>
        <p className="mt-2 max-w-3xl text-sm text-gray-400">
          Explore versões públicas, tendências e downloads em uma experiência de feed contínuo.
        </p>
      </section>

      <section className="social-layout">
        <aside className="space-y-4">
          <div className="social-side-card">
            <p className="text-xs font-semibold uppercase tracking-widest text-gray-500">Explorar</p>
            <div className="mt-3 space-y-2 text-sm text-gray-200">
              <div className="social-tile flex items-center gap-2">
                <Compass className="h-4 w-4 text-cyan-300" />
                Novos pacotes
              </div>
              <div className="social-tile flex items-center gap-2">
                <Globe2 className="h-4 w-4 text-cyan-300" />
                Mais baixados
              </div>
              <div className="social-tile flex items-center gap-2">
                <Share2 className="h-4 w-4 text-cyan-300" />
                Recomendados
              </div>
            </div>
          </div>
          <div className="social-side-card text-sm text-gray-200">
            <p className="text-xs font-semibold uppercase tracking-widest text-gray-500">Atalhos</p>
            <div className="mt-3 space-y-2">
              <Link href="/repository" className="social-link">Abrir repositório</Link>
              <Link href="/dashboard" className="social-link">Voltar ao feed</Link>
            </div>
          </div>
        </aside>

        <main>
          <PublicCatalogPanel />
        </main>

        <aside className="space-y-4">
          <div className="social-side-card">
            <div className="flex items-center gap-2">
              <Flame className="h-4 w-4 text-orange-300" />
              <p className="text-xs font-semibold uppercase tracking-widest text-gray-500">Tendências</p>
            </div>
            <div className="mt-3 space-y-2 text-sm text-gray-200">
              <div className="social-tile">#public-release</div>
              <div className="social-tile">#checksum-verified</div>
              <div className="social-tile">#latest-stable</div>
            </div>
          </div>
          <div className="social-side-card border-emerald-400/35 bg-emerald-400/10 text-sm text-emerald-100">
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
