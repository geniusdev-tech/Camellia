import FileExplorer from '../components/features/FileExplorer'
import ProcessPanel from '../components/features/ProcessPanel'

export default function DashboardPage() {
    return (
        <div className="h-full flex flex-col gap-6">
            {/* File Explorer */}
            <div className="flex-1 min-h-0">
                <FileExplorer />
            </div>

            {/* Process Panel */}
            <div className="flex-shrink-0">
                <ProcessPanel />
            </div>
        </div>
    )
}
