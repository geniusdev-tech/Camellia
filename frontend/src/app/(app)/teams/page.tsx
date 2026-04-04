import Link from 'next/link'
import { Flame, Handshake, ShieldCheck, Users } from 'lucide-react'
import { TeamsPanel } from '@/components/features/TeamsPanel'

export default function TeamsPage() {
  return (
    <div className="social-page">
      <section className="social-hero">
        <p className="text-xs font-mono uppercase tracking-[0.2em] text-cyan-300">Feed de Times</p>
        <h1 className="mt-2 text-3xl font-bold text-white">Relações, convites e grants</h1>
        <p className="mt-2 max-w-3xl text-sm text-gray-400">
          Gerencie colaboração entre squads com convites, papéis e compartilhamento de projetos.
        </p>
      </section>

      <section className="social-layout">
        <aside className="space-y-4">
          <div className="social-side-card">
            <p className="text-xs font-semibold uppercase tracking-widest text-gray-500">Espaços</p>
            <div className="mt-3 space-y-2 text-sm text-gray-200">
              <div className="social-tile">Donos</div>
              <div className="social-tile">Grupo de Escrita</div>
              <div className="social-tile">Hub de Leitura</div>
            </div>
          </div>
          <div className="social-side-card">
            <p className="text-xs font-semibold uppercase tracking-widest text-gray-500">Navegação</p>
            <div className="mt-3 space-y-2">
              <Link href="/dashboard" className="social-link">Voltar ao dashboard</Link>
              <Link href="/repository" className="social-link">Ver repositório</Link>
            </div>
          </div>
        </aside>

        <main>
          <TeamsPanel />
        </main>

        <aside className="space-y-4">
          <div className="social-side-card">
            <div className="flex items-center gap-2">
              <Flame className="h-4 w-4 text-orange-300" />
              <p className="text-xs font-semibold uppercase tracking-widest text-gray-500">Em alta</p>
            </div>
            <div className="mt-3 space-y-2 text-sm text-gray-200">
              <div className="social-tile">#team-grants</div>
              <div className="social-tile">#invite-flow</div>
              <div className="social-tile">#rbac</div>
            </div>
          </div>
          <div className="social-side-card text-sm text-gray-200">
            <div className="inline-flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-cyan-300" />
              Boas práticas
            </div>
            <p className="mt-2 text-xs text-gray-500">Evite grants permanentes para equipes temporárias. Prefira expiração em convites.</p>
          </div>
          <Link href="/ops" className="h-btn-primary w-full">
            <Handshake className="h-4 w-4" />
            Integrar com operações
          </Link>
          <div className="social-tile flex items-center gap-2 text-sm">
            <Users className="h-4 w-4 text-cyan-300" />
            Colaboração ativa
          </div>
        </aside>
      </section>
    </div>
  )
}
