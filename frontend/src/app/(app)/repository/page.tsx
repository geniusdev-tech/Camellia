import { ProjectUploader } from '@/components/features/ProjectUploader'
import { RepositoryControlCenter } from '@/components/features/RepositoryControlCenter'

export default function RepositoryPage() {
  return (
    <div className="mx-auto flex max-w-7xl flex-col gap-5">
      <ProjectUploader />
      <RepositoryControlCenter />
    </div>
  )
}
