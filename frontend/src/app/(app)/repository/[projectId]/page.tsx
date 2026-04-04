import { ProjectUploader } from '@/components/features/ProjectUploader'
import { RepositoryControlCenter } from '@/components/features/RepositoryControlCenter'

export default async function RepositoryDetailPage({
  params,
}: {
  params: Promise<{ projectId: string }>
}) {
  const { projectId } = await params

  return (
    <div className="mx-auto flex max-w-7xl flex-col gap-5">
      <ProjectUploader />
      <RepositoryControlCenter currentProjectId={projectId} />
    </div>
  )
}

export async function generateStaticParams() {
  // Substitua esta lógica com os IDs reais dos projetos
  const projectIds = ['project1', 'project2', 'project3']

  return projectIds.map((projectId) => ({ projectId }))
}
