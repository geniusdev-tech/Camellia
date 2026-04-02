import { Suspense } from 'react'
import { FileExplorer } from '@/components/features/FileExplorer'
import { ProcessPanel } from '@/components/features/ProcessPanel'
import { ProjectUploader } from '@/components/features/ProjectUploader'
import { StatsBar } from '@/components/features/StatsBar'

export default function DashboardPage() {
  return (
    <div className="flex flex-col gap-5 max-w-6xl mx-auto">
      <StatsBar />
      <ProjectUploader />

      <div className="grid grid-cols-1 xl:grid-cols-[1fr_360px] gap-5">
        {/* File explorer */}
        <Suspense fallback={<div className="h-96 glass rounded-2xl animate-pulse" />}>
          <FileExplorer />
        </Suspense>

        {/* Process panel */}
        <div className="flex flex-col gap-4">
          <ProcessPanel />
        </div>
      </div>
    </div>
  )
}
