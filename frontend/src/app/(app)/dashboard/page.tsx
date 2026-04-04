import Link from 'next/link'
import {
  ActivitySquare,
  ArrowRight,
  Bookmark,
  Flame,
  FolderGit2,
  Globe2,
  Heart,
  MessageCircle,
  Repeat2,
  ShieldCheck,
  UserPlus,
  Users,
} from 'lucide-react'
import { StatsBar } from '@/components/features/StatsBar'

const areas = [
  {
    href: '/repository',
    title: 'Repositório',
    description: 'Acesso a releases, versionamento e políticas de distribuição.',
    icon: FolderGit2,
  },
  {
    href: '/teams',
    title: 'Times',
    description: 'Gestão de equipes, permissões e roles de acesso.',
    icon: Users,
  },
  {
    href: '/ops',
    title: 'Operações',
    description: 'Jobs assíncronos, scans de segurança e métricas do sistema.',
    icon: ActivitySquare,
  },
  {
    href: '/catalog',
    title: 'Catálogo',
    description: 'Descoberta de releases públicas e downloads.',
    icon: Globe2,
  },
]

export default function DashboardPage() {
  const trends = ['#release-stable', '#security-scan', '#team-ops', '#catalog-publico']

  return (
    <div className="mx-auto max-w-7xl px-4 py-6 lg:px-6">
      <section className="mb-6 rounded-3xl border border-white/10 bg-dark-900/50 p-5 backdrop-blur">
        <p className="text-xs font-mono uppercase tracking-[0.2em] text-cyan-300">Feed Principal</p>
        <h1 className="mt-2 text-3xl font-bold leading-tight text-white">
          Feed de releases, times e operações
        </h1>
        <p className="mt-2 max-w-3xl text-sm text-gray-400">
          Acompanhe atividade em tempo real, veja tendências e entre direto nos módulos principais.
        </p>
      </section>

      <StatsBar />

      <section className="mt-6 grid gap-5 xl:grid-cols-[260px_minmax(0,1fr)_280px]">
        <aside className="space-y-4">
          <div className="rounded-3xl border border-white/10 bg-dark-900/60 p-4 backdrop-blur">
            <p className="text-xs font-semibold uppercase tracking-widest text-gray-500">Comunidades</p>
            <div className="mt-3 space-y-2">
              <button className="flex w-full items-center justify-between rounded-2xl bg-primary-600/15 px-3 py-2 text-sm text-primary-100">
                Observatório de Segurança
                <span className="rounded-full bg-white/15 px-2 py-0.5 text-[10px]">42</span>
              </button>
              <button className="flex w-full items-center justify-between rounded-2xl bg-white/5 px-3 py-2 text-sm text-gray-200">
                Operações de Release
                <span className="rounded-full bg-white/10 px-2 py-0.5 text-[10px]">17</span>
              </button>
              <button className="flex w-full items-center justify-between rounded-2xl bg-white/5 px-3 py-2 text-sm text-gray-200">
                Hub de Times
                <span className="rounded-full bg-white/10 px-2 py-0.5 text-[10px]">9</span>
              </button>
            </div>
          </div>

          <div className="rounded-3xl border border-white/10 bg-dark-900/60 p-4 backdrop-blur">
            <p className="text-xs font-semibold uppercase tracking-widest text-gray-500">Atalhos</p>
            <div className="mt-3 space-y-2">
              <Link href="/repository" className="block rounded-2xl bg-white/5 px-3 py-2 text-sm text-gray-200 hover:bg-white/10">
                Ver repositório
              </Link>
              <Link href="/ops" className="block rounded-2xl bg-white/5 px-3 py-2 text-sm text-gray-200 hover:bg-white/10">
                Ver operações
              </Link>
            </div>
          </div>
        </aside>

        <main className="space-y-4">
          {areas.map(({ href, title, description, icon: Icon }) => (
            <article key={href} className="rounded-3xl border border-white/10 bg-dark-900/60 p-5 backdrop-blur">
              <div className="flex items-start justify-between gap-4">
                <div className="flex items-start gap-3">
                  <div className="mt-0.5 flex h-11 w-11 items-center justify-center rounded-2xl bg-gradient-to-br from-cyan-500/30 to-green-400/20 text-cyan-200">
                    <Icon className="h-5 w-5" />
                  </div>
                  <div>
                    <p className="text-xs uppercase tracking-widest text-gray-500">Atualização</p>
                    <h3 className="mt-1 text-lg font-semibold text-white">{title}</h3>
                    <p className="mt-1 text-sm text-gray-400">{description}</p>
                  </div>
                </div>
                <button className="rounded-full p-2 text-gray-500 hover:bg-white/10 hover:text-white">
                  <Bookmark className="h-4 w-4" />
                </button>
              </div>

              <div className="mt-4 flex items-center gap-4 text-xs text-gray-400">
                <span className="inline-flex items-center gap-1">
                  <Heart className="h-3.5 w-3.5" /> 24
                </span>
                <span className="inline-flex items-center gap-1">
                  <MessageCircle className="h-3.5 w-3.5" /> 8
                </span>
                <span className="inline-flex items-center gap-1">
                  <Repeat2 className="h-3.5 w-3.5" /> 5
                </span>
                <Link href={href} className="ml-auto inline-flex items-center gap-1 text-cyan-300 hover:text-cyan-200">
                  Abrir módulo <ArrowRight className="h-3.5 w-3.5" />
                </Link>
              </div>
            </article>
          ))}
        </main>

        <aside className="space-y-4">
          <div className="rounded-3xl border border-white/10 bg-dark-900/60 p-4 backdrop-blur">
            <div className="flex items-center gap-2">
              <Flame className="h-4 w-4 text-orange-300" />
              <p className="text-xs font-semibold uppercase tracking-widest text-gray-500">Tendências</p>
            </div>
            <div className="mt-3 space-y-2">
              {trends.map((trend) => (
                <button key={trend} className="flex w-full items-center justify-between rounded-2xl bg-white/5 px-3 py-2 text-sm text-gray-200 hover:bg-white/10">
                  {trend}
                  <span className="text-xs text-gray-500">em alta</span>
                </button>
              ))}
            </div>
          </div>

          <div className="rounded-3xl border border-white/10 bg-dark-900/60 p-4 backdrop-blur">
            <p className="text-xs font-semibold uppercase tracking-widest text-gray-500">Pessoas sugeridas</p>
            <div className="mt-3 space-y-3">
              <div className="flex items-center justify-between rounded-2xl bg-white/5 px-3 py-2">
                <div>
                  <p className="text-sm text-white">Equipe Security</p>
                  <p className="text-xs text-gray-500">compliance e triagem</p>
                </div>
                <button className="rounded-xl bg-primary-500/20 px-2 py-1 text-xs text-primary-200">
                  <UserPlus className="h-3.5 w-3.5" />
                </button>
              </div>
              <div className="flex items-center justify-between rounded-2xl bg-white/5 px-3 py-2">
                <div>
                  <p className="text-sm text-white">Núcleo de Operações</p>
                  <p className="text-xs text-gray-500">release e rollback</p>
                </div>
                <button className="rounded-xl bg-primary-500/20 px-2 py-1 text-xs text-primary-200">
                  <UserPlus className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
          </div>

          <Link
            href="/teams"
            className="flex items-center justify-between rounded-3xl border border-emerald-400/20 bg-emerald-400/10 px-4 py-3 text-sm text-emerald-100"
          >
            <span className="inline-flex items-center gap-2">
              <ShieldCheck className="h-4 w-4" />
              Gerenciar equipes
            </span>
            <ArrowRight className="h-4 w-4" />
          </Link>
        </aside>
      </section>

      <section className="mt-6 grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {areas.map(({ href, title, icon: Icon }) => (
          <Link
            key={`quick-${href}`}
            href={href}
            className="group rounded-2xl border border-white/10 bg-dark-900/40 px-4 py-3 transition hover:border-cyan-400/40 hover:bg-dark-900/70"
          >
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-cyan-500/15 text-cyan-300">
                <Icon className="h-4 w-4" />
              </div>
              <div>
                <p className="text-sm font-medium text-white">{title}</p>
                <p className="text-xs text-gray-500">Entrar</p>
              </div>
            </div>
          </Link>
        ))}
      </section>
    </div>
  )
}
