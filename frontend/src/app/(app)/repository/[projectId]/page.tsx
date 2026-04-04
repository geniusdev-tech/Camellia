import Link from 'next/link'
import { Flame, UploadCloud, Workflow } from 'lucide-react'
import { ProjectUploader } from '@/components/features/ProjectUploader'
import { RepositoryControlCenter } from '@/components/features/RepositoryControlCenter'

export default async function RepositoryDetailPage({
  params,
}: {
  params: Promise<{ projectId: string }>
}) {
  const { projectId } = await params

  return (
    <div className="social-page">
      <section className="social-hero">
        <p className="text-xs font-mono uppercase tracking-[0.2em] text-cyan-300">Detalhe do Repositório</p>
        <h1 className="mt-2 text-3xl font-bold text-white">Thread da release #{projectId.slice(0, 8)}</h1>
        <p className="mt-2 max-w-3xl text-sm text-gray-400">
          Gerencie upload, status, grants e workflow deste pacote no mesmo fluxo.
        </p>
      </section>

      <section className="social-layout">
        <aside className="space-y-4">
          <div className="social-side-card">
            <p className="text-xs font-semibold uppercase tracking-widest text-gray-500">Ações</p>
            <div className="mt-3 space-y-2 text-sm text-gray-200">
              <Link href="/repository" className="social-link">Voltar para lista</Link>
              <Link href="/ops" className="social-link">Abrir operações</Link>
            </div>
          </div>
          <div className="social-side-card">
            <div className="inline-flex items-center gap-2 text-sm text-white">
              <UploadCloud className="h-4 w-4 text-cyan-300" />
              Upload seguro
            </div>
            <p className="mt-2 text-xs text-gray-500">Mantenha descrição, changelog e checksum consistentes por versão.</p>
          </div>
        </aside>

        <main className="space-y-5">
          <ProjectUploader />
          <RepositoryControlCenter currentProjectId={projectId} />
        </main>

        <aside className="space-y-4">
          <div className="social-side-card">
            <div className="flex items-center gap-2">
              <Flame className="h-4 w-4 text-orange-300" />
              <p className="text-xs font-semibold uppercase tracking-widest text-gray-500">Sinais</p>
            </div>
            <div className="mt-3 space-y-2 text-sm text-gray-200">
              <div className="social-tile">#release-quality</div>
              <div className="social-tile">#pipeline-status</div>
              <div className="social-tile">#acl-review</div>
            </div>
          </div>
          <div className="social-side-card">
            <div className="inline-flex items-center gap-2 text-sm text-white">
              <Workflow className="h-4 w-4 text-cyan-300" />
              Dica de fluxo
            </div>
            <p className="mt-2 text-xs text-gray-500">Promova por etapas e acompanhe jobs antes de publicar em produção.</p>
          </div>
        </aside>
      </section>
    </div>
  )
}

export async function generateStaticParams() {
  // Substitua esta lógica com os IDs reais dos projetos
  const projectIds = ['project1', 'project2', 'project3']

  return projectIds.map((projectId) => ({ projectId }))
}
