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
