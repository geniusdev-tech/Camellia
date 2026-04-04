import Link from 'next/link'
import { Flame, Handshake, ShieldCheck, Users } from 'lucide-react'
import { TeamsPanel } from '@/components/features/TeamsPanel'

export default function TeamsPage() {
  return (
    <div className="mx-auto max-w-7xl px-4 py-6 lg:px-6">
      <section className="mb-6 rounded-3xl border border-white/10 bg-dark-900/50 p-5 backdrop-blur">
        <p className="text-xs font-mono uppercase tracking-[0.2em] text-cyan-300">Feed de Times</p>
        <h1 className="mt-2 text-3xl font-bold text-white">Relações, convites e grants</h1>
        <p className="mt-2 max-w-3xl text-sm text-gray-400">
          Gerencie colaboração entre squads com convites, papéis e compartilhamento de projetos.
        </p>
      </section>

      <section className="grid gap-5 xl:grid-cols-[260px_minmax(0,1fr)_280px]">
        <aside className="space-y-4">
          <div className="rounded-3xl border border-white/10 bg-dark-900/60 p-4">
            <p className="text-xs font-semibold uppercase tracking-widest text-gray-500">Espaços</p>
            <div className="mt-3 space-y-2 text-sm text-gray-200">
              <div className="rounded-2xl bg-white/5 px-3 py-2">Donos</div>
              <div className="rounded-2xl bg-white/5 px-3 py-2">Grupo de Escrita</div>
              <div className="rounded-2xl bg-white/5 px-3 py-2">Hub de Leitura</div>
            </div>
          </div>
          <div className="rounded-3xl border border-white/10 bg-dark-900/60 p-4">
            <p className="text-xs font-semibold uppercase tracking-widest text-gray-500">Navegação</p>
            <div className="mt-3 space-y-2">
              <Link href="/dashboard" className="block rounded-2xl bg-white/5 px-3 py-2 text-sm text-gray-200 hover:bg-white/10">Voltar ao dashboard</Link>
              <Link href="/repository" className="block rounded-2xl bg-white/5 px-3 py-2 text-sm text-gray-200 hover:bg-white/10">Ver repositório</Link>
            </div>
          </div>
        </aside>

        <main>
          <TeamsPanel />
        </main>

        <aside className="space-y-4">
          <div className="rounded-3xl border border-white/10 bg-dark-900/60 p-4">
            <div className="flex items-center gap-2">
              <Flame className="h-4 w-4 text-orange-300" />
              <p className="text-xs font-semibold uppercase tracking-widest text-gray-500">Em alta</p>
            </div>
            <div className="mt-3 space-y-2 text-sm text-gray-200">
              <div className="rounded-2xl bg-white/5 px-3 py-2">#team-grants</div>
              <div className="rounded-2xl bg-white/5 px-3 py-2">#invite-flow</div>
              <div className="rounded-2xl bg-white/5 px-3 py-2">#rbac</div>
            </div>
          </div>
          <div className="rounded-3xl border border-white/10 bg-dark-900/60 p-4 text-sm text-gray-200">
            <div className="inline-flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-cyan-300" />
              Boas práticas
            </div>
            <p className="mt-2 text-xs text-gray-500">Evite grants permanentes para equipes temporárias. Prefira expiração em convites.</p>
          </div>
          <Link href="/ops" className="flex items-center gap-2 rounded-2xl border border-emerald-400/20 bg-emerald-400/10 px-3 py-2 text-sm text-emerald-100">
            <Handshake className="h-4 w-4" />
            Integrar com operações
          </Link>
          <div className="flex items-center gap-2 rounded-2xl border border-white/10 bg-white/5 px-3 py-2 text-sm text-gray-200">
            <Users className="h-4 w-4 text-cyan-300" />
            Colaboração ativa
          </div>
        </aside>
      </section>
    </div>
  )
}
