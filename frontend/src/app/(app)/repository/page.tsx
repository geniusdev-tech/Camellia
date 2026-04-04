import Link from 'next/link'
import { Flame, Library, Sparkles, Users } from 'lucide-react'
import { ReleaseControlCenter } from '@/components/features/ReleaseControlCenter'

export default function RepositoryPage() {
  return (
    <div className="social-page">
      <section className="social-hero">
        <p className="text-xs font-mono uppercase tracking-[0.2em] text-cyan-300">Feed do Repositório</p>
        <h1 className="mt-2 text-3xl font-bold text-white">Timeline de releases</h1>
        <p className="mt-2 max-w-3xl text-sm text-gray-400">
          Navegue por versões, publique atualizações e acompanhe o estado do repositório como um feed de atividade.
        </p>
      </section>

      <section className="social-layout">
        <aside className="space-y-4">
          <div className="social-side-card">
            <p className="text-xs font-semibold uppercase tracking-widest text-gray-500">Comunidades ativas</p>
            <div className="mt-3 space-y-2">
              <div className="social-tile text-sm">Engenharia de Releases</div>
              <div className="social-tile text-sm">Revisão de Catálogo</div>
              <div className="social-tile text-sm">Time de Segurança</div>
            </div>
          </div>
          <div className="social-side-card">
            <p className="text-xs font-semibold uppercase tracking-widest text-gray-500">Atalhos</p>
            <div className="mt-3 space-y-2">
              <Link href="/dashboard" className="social-link">Voltar ao feed</Link>
              <Link href="/ops" className="social-link">Ver operações</Link>
            </div>
          </div>
        </aside>

        <main>
          <ReleaseControlCenter />
        </main>

        <aside className="space-y-4">
          <div className="social-side-card">
            <div className="flex items-center gap-2">
              <Flame className="h-4 w-4 text-orange-300" />
              <p className="text-xs font-semibold uppercase tracking-widest text-gray-500">Tendências</p>
            </div>
            <div className="mt-3 space-y-2 text-sm text-gray-200">
              <div className="social-tile">#stable-publish</div>
              <div className="social-tile">#rollback-safe</div>
              <div className="social-tile">#supply-chain</div>
            </div>
          </div>
          <div className="social-side-card">
            <div className="flex items-center gap-2 text-sm text-white">
              <Library className="h-4 w-4 text-cyan-300" />
              Curadoria
            </div>
            <p className="mt-2 text-xs text-gray-500">Mantenha versões com changelog e metadados completos para melhorar a descoberta.</p>
          </div>
          <div className="social-side-card border-emerald-400/35 bg-emerald-400/10 text-sm text-emerald-100">
            <div className="inline-flex items-center gap-2">
              <Sparkles className="h-4 w-4" />
              Publicar com confiança
            </div>
            <p className="mt-2 text-xs text-emerald-200/90">Use fluxos e validações antes de promover para produção.</p>
          </div>
          <Link href="/teams" className="social-link inline-flex items-center gap-2">
            <Users className="h-4 w-4 text-cyan-300" />
            Compartilhar com times
          </Link>
        </aside>
      </section>
    </div>
  )
}
