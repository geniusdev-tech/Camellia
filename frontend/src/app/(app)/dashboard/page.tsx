import Link from 'next/link'
import { ActivitySquare, ArrowRight, FolderGit2, Globe2, Users } from 'lucide-react'
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
    description: 'Discover de releases públicas e downloads.',
    icon: Globe2,
  },
]

export default function DashboardPage() {
  return (
    <div className="mx-auto max-w-7xl px-6 py-12 space-y-12">
      {/* Header */}
      <section className="space-y-4">
        <div>
          <p className="text-sm font-mono text-green-400 mb-2">DASHBOARD</p>
          <h1 className="text-4xl font-bold leading-tight">
            Bem-vindo ao GateStack.
          </h1>
          <p className="mt-2 text-gray-400 max-w-2xl text-lg">
            Conformidade, segurança e inteligência em tempo real para suas releases.
          </p>
        </div>
      </section>

      <StatsBar />

      {/* Areas Grid */}
      <section className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
        {areas.map(({ href, title, description, icon: Icon }) => (
          <Link
            key={href}
            href={href}
            className="group bg-dark-900/30 border border-white/5 rounded-lg p-6 hover:border-green-400/50 hover:bg-dark-800/30 transition-all"
          >
            <div className="inline-flex h-12 w-12 items-center justify-center rounded-lg bg-green-400/10 text-green-400 mb-4">
              <Icon className="h-6 w-6" />
            </div>
            <h3 className="text-lg font-semibold text-white">{title}</h3>
            <p className="mt-2 text-sm text-gray-400 leading-relaxed">{description}</p>
            <div className="mt-4 inline-flex items-center gap-2 text-sm text-green-400 group-hover:translate-x-1 transition-transform">
              Acessar
              <ArrowRight className="h-4 w-4" />
            </div>
          </Link>
        ))}
      </section>
    </div>
  )
}
