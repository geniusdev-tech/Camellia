'use client'
import { useQuery } from '@tanstack/react-query'
import { Boxes, CalendarRange, FolderGit2, Sparkles } from 'lucide-react'
import { projectsAPI } from '@/lib/api'

function Stat({ icon: Icon, label, value, sub, accent = false }: {
  icon: React.ElementType
  label: string
  value: string
  sub?: string
  accent?: boolean
}) {
  return (
    <div className="glass flex items-center gap-4 rounded-xl px-5 py-4">
      <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-xl ${accent ? 'bg-cyan-400/10 border border-cyan-400/15 text-cyan-400' : 'bg-green-400/10 border border-green-400/15 text-green-400'}`}>
        <Icon className="h-5 w-5" />
      </div>
      <div>
        <p className="font-mono text-[10px] font-medium uppercase tracking-[0.2em] text-gray-500">{label}</p>
        <p className="text-lg font-bold leading-tight text-white">{value}</p>
        {sub ? <p className="mt-0.5 font-mono text-[10px] text-gray-500">{sub}</p> : null}
      </div>
    </div>
  )
}

export function StatsBar() {
  const { data } = useQuery({
    queryKey: ['projects', 'summary'],
    queryFn: () => projectsAPI.list({ page_size: 100, sort_by: 'created_at', sort_dir: 'desc' }),
    staleTime: 30_000,
  })

  const projects = data?.projects ?? []
  const total = data?.pagination?.total ?? projects.length
  const published = projects.filter((project) => project.lifecycle_status === 'published').length
  const latestMonth = projects[0]
    ? new Date(projects[0].created_at).toLocaleDateString('pt-BR', { month: 'short', year: 'numeric' })
    : 'sem envios'
  const packageCount = new Set(projects.map((project) => project.package_name)).size
  const totalSizeMb = projects.reduce((sum, project) => sum + project.size_bytes, 0) / (1024 * 1024)

  return (
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
      <Stat icon={FolderGit2} label="Releases Visíveis" value={String(total)} sub={`${published} publicadas`} accent />
      <Stat icon={Boxes} label="Pacotes" value={String(packageCount)} sub="namespaces distintos" />
      <Stat icon={CalendarRange} label="Última Atualização" value={latestMonth} sub="ordem pelo backend" accent />
      <Stat icon={Sparkles} label="Volume" value={`${totalSizeMb.toFixed(totalSizeMb >= 10 ? 0 : 1)} MB`} sub="artefatos indexados" />
    </div>
  )
}
