import Link from 'next/link'
import { ActivitySquare, ArrowRight, FolderGit2, Globe2, Users } from 'lucide-react'
import { StatsBar } from '@/components/features/StatsBar'

const areas = [
  {
    href: '/repository',
    title: 'Repositório',
    text: 'Busca, paginação, detalhe, workflow, metadata, grants e downloads assinados.',
    icon: FolderGit2,
  },
  {
    href: '/teams',
    title: 'Times',
    text: 'Times, convites e grants por equipe sobre os pacotes do repositório.',
    icon: Users,
  },
  {
    href: '/ops',
    title: 'Operações',
    text: 'Jobs assíncronos, scans, publish e métricas operacionais do backend.',
    icon: ActivitySquare,
  },
  {
    href: '/catalog',
    title: 'Catálogo Público',
    text: 'Consulta de releases públicas, latest, versões e download externo.',
    icon: Globe2,
  },
]

export default function DashboardPage() {
  return (
    <div className="mx-auto flex max-w-7xl flex-col gap-5">
      <section className="relative overflow-hidden rounded-[28px] border border-white/10 bg-gradient-to-br from-primary-900 via-dark-850 to-accent-900/50 p-6 lg:p-8">
        <div className="absolute inset-y-0 right-0 w-1/2 bg-[radial-gradient(circle_at_top_right,rgba(0,212,170,0.18),transparent_55%)]" />
        <div className="relative">
          <span className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/5 px-3 py-1 text-xs uppercase tracking-[0.24em] text-gray-300">
            GateStack Console
          </span>
          <h1 className="mt-4 max-w-3xl text-3xl font-bold leading-tight text-white font-display lg:text-5xl">
            A plataforma agora está dividida por domínio operacional.
          </h1>
          <p className="mt-4 max-w-3xl text-sm leading-6 text-gray-300 lg:text-base">
            Use o overview para leitura rápida e entre nas áreas dedicadas para trabalhar com repositório, times, operações e catálogo.
          </p>
        </div>
      </section>

      <StatsBar />

      <section className="grid gap-4 lg:grid-cols-2 xl:grid-cols-4">
        {areas.map(({ href, title, text, icon: Icon }) => (
          <Link
            key={href}
            href={href}
            className="glass group rounded-2xl p-5 transition-transform duration-200 hover:-translate-y-1"
          >
            <div className="mb-4 flex h-11 w-11 items-center justify-center rounded-2xl bg-accent/10 text-accent">
              <Icon className="h-5 w-5" />
            </div>
            <div className="text-lg font-semibold text-white">{title}</div>
            <p className="mt-2 text-sm leading-6 text-gray-400">{text}</p>
            <div className="mt-4 inline-flex items-center gap-2 text-sm text-accent">
              Abrir área
              <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-1" />
            </div>
          </Link>
        ))}
      </section>
    </div>
  )
}
