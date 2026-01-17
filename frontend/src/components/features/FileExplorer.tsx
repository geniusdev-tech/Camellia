import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ChevronUp, RefreshCw, File, Folder, Lock, HardDrive, Usb, Shield } from 'lucide-react'
import { clsx } from 'clsx'
import { deviceAPI, vaultAPI } from '../../api/client'
import { useVaultStore } from '../../store/vaultStore'
import Modal from '../ui/Modal'
import SecurityReport from './SecurityReport'

// Helper
const formatBytes = (bytes: number, decimals = 2) => {
    if (!+bytes) return '0 B'
    const k = 1024
    const dm = decimals < 0 ? 0 : decimals
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`
}

export default function FileExplorer() {
    const {
        currentPath,
        currentDevice,
        selectedFiles,
        setCurrentPath,
        setCurrentDevice,
        toggleFileSelection,
        clearSelection
    } = useVaultStore()

    const [devices, setDevices] = useState<{ id: string, name: string, type: string }[]>([])

    // Scan State
    const [scanReport, setScanReport] = useState<any>(null)
    const [isScanModalOpen, setIsScanModalOpen] = useState(false)
    const [isScanning, setIsScanning] = useState(false)

    // Fetch Devices (Real Polling)
    const { data: deviceData } = useQuery({
        queryKey: ['devices'],
        queryFn: deviceAPI.listDevices,
        refetchInterval: 3000 // Fast polling for USB detection
    })

    useEffect(() => {
        if (deviceData?.devices) {
            setDevices(deviceData.devices)
        }
    }, [deviceData])

    const { data, isLoading, error } = useQuery({
        queryKey: ['files', currentPath, currentDevice],
        queryFn: () => vaultAPI.listFiles({ path: currentPath, device_id: currentDevice || 'local' }),
        refetchInterval: 5000 // Auto refresh
    })

    const files = data?.items || []

    const handleFileClick = (file: any) => {
        if (file.is_dir) {
            setCurrentPath(file.path)
            clearSelection()
        } else {
            toggleFileSelection(file.path)
        }
    }

    const handleNavigateUp = () => {
        if (currentPath === '/' || currentPath === '') return
        const parent = currentPath.split('/').slice(0, -1).join('/') || '/'
        setCurrentPath(parent)
        clearSelection()
    }

    const handleScanFile = async (path: string) => {
        setIsScanning(true)
        try {
            const report = await vaultAPI.scanFile(path)
            setScanReport(report)
            setIsScanModalOpen(true)
        } catch (err: any) {
            alert('Falha no scan: ' + err.message)
        } finally {
            setIsScanning(false)
        }
    }

    // Mobile File Card Component
    const FileCard = ({ file, isSelected, onToggle, onClick }: any) => (
        <div
            className={clsx(
                "flex items-center gap-3 p-3 rounded-xl border mb-2 active:scale-[0.98] transition-all",
                isSelected
                    ? "bg-primary/5 border-primary dark:bg-primary/10"
                    : "bg-white dark:bg-dark-800 border-gray-200 dark:border-dark-700"
            )}
            onClick={onClick}
        >
            <div className="relative shrink-0">
                {file.is_dir ? (
                    <Folder className="w-10 h-10 text-yellow-500 fill-yellow-500/20" />
                ) : file.is_encrypted ? (
                    <Lock className="w-10 h-10 text-secondary fill-secondary/20" />
                ) : (
                    <File className="w-10 h-10 text-gray-400" />
                )}
            </div>

            <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-gray-900 dark:text-white truncate">
                    {file.name}
                </p>
                <div className="flex items-center gap-2 mt-0.5">
                    <span className="text-xs text-gray-500 dark:text-gray-400">
                        {file.size > 0 ? formatBytes(file.size) : (file.is_dir ? 'Pasta' : '0 B')}
                    </span>
                    {!file.is_dir && (
                        <button
                            onClick={(e) => { e.stopPropagation(); handleScanFile(file.path) }}
                            className="p-1 hover:bg-gray-100 dark:hover:bg-dark-700 rounded text-gray-400 hover:text-primary transition-colors"
                            title="Verificar Integridade"
                        >
                            <Shield className="w-3 h-3" />
                        </button>
                    )}
                </div>
            </div>

            <div onClick={(e) => e.stopPropagation()}>
                <input
                    type="checkbox"
                    checked={isSelected}
                    onChange={() => onToggle(file.path)}
                    className="w-5 h-5 rounded border-gray-300 text-primary focus:ring-primary"
                />
            </div>
        </div>
    )

    return (
        <div className="space-y-4">
            {/* Header / Device Selector */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-white dark:bg-dark-900 p-4 rounded-xl border border-gray-200 dark:border-dark-800 shadow-sm">
                <div className="flex items-center gap-2 overflow-x-auto pb-2 sm:pb-0 scrollbar-hide">
                    {devices.map(device => (
                        <button
                            key={device.id}
                            onClick={() => setCurrentDevice(device.id)}
                            className={clsx(
                                'flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium whitespace-nowrap transition-colors',
                                currentDevice === device.id
                                    ? 'bg-primary text-white shadow-md'
                                    : 'text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-dark-800'
                            )}
                        >
                            {device.type === 'usb' ? <Usb className="w-4 h-4" /> : <HardDrive className="w-4 h-4" />}
                            {device.name}
                        </button>
                    ))}
                </div>

                {/* Path Breadcrumbs */}
                <div className="flex items-center gap-2 text-sm text-gray-500 dark:text-gray-400 bg-gray-50 dark:bg-dark-950 px-3 py-1.5 rounded-lg border border-gray-200 dark:border-dark-800 overflow-hidden w-full sm:w-auto">
                    <span className="truncate flex-1 sm:flex-none" dir="rtl">{currentPath || '/'}</span>
                    {currentPath !== '/' && currentPath !== '' && (
                        <button onClick={handleNavigateUp} className="p-1 hover:text-primary transition-colors shrink-0">
                            <ChevronUp className="w-4 h-4" />
                        </button>
                    )}
                </div>
            </div>

            {/* Error Message */}
            {error && (
                <div className="p-4 rounded-xl bg-danger/10 text-danger border border-danger/20 text-sm">
                    {(error as Error).message}
                </div>
            )}

            {/* File List */}
            <div className="bg-white dark:bg-dark-900 rounded-xl border border-gray-200 dark:border-dark-800 shadow-sm overflow-hidden min-h-[400px]">
                {isLoading ? (
                    <div className="flex flex-col items-center justify-center py-20 text-gray-400">
                        <RefreshCw className="w-8 h-8 animate-spin mb-2" />
                        <p className="text-sm">Carregando arquivos...</p>
                    </div>
                ) : files.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-20 text-gray-400">
                        <Folder className="w-12 h-12 mb-2 opacity-20" />
                        <p className="text-sm">Pasta vazia</p>
                    </div>
                ) : (
                    <>
                        {/* Desktop Table View (Hidden on Mobile) */}
                        <div className="hidden sm:block overflow-x-auto">
                            <table className="w-full text-left text-sm">
                                <thead className="bg-gray-50 dark:bg-dark-950 border-b border-gray-200 dark:border-dark-800">
                                    <tr>
                                        <th className="px-4 py-3 font-medium text-gray-500 dark:text-gray-400 w-12">
                                            <div className="w-4 h-4" />
                                        </th>
                                        <th className="px-4 py-3 font-medium text-gray-500 dark:text-gray-400">Nome</th>
                                        <th className="px-4 py-3 font-medium text-gray-500 dark:text-gray-400">Ações</th>
                                        <th className="px-4 py-3 font-medium text-gray-500 dark:text-gray-400">Tamanho</th>
                                        <th className="px-4 py-3 font-medium text-gray-500 dark:text-gray-400">Tipo</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-gray-100 dark:divide-dark-800">
                                    {files.map((file: any) => (
                                        <tr
                                            key={file.path}
                                            className={clsx(
                                                "hover:bg-gray-50 dark:hover:bg-dark-800/50 transition-colors cursor-pointer",
                                                selectedFiles.has(file.path) && "bg-primary/5 dark:bg-primary/10"
                                            )}
                                            onClick={() => handleFileClick(file)}
                                        >
                                            <td className="px-4 py-3" onClick={e => e.stopPropagation()}>
                                                <input
                                                    type="checkbox"
                                                    checked={selectedFiles.has(file.path)}
                                                    onChange={() => toggleFileSelection(file.path)}
                                                    className="rounded border-gray-300 text-primary focus:ring-primary"
                                                />
                                            </td>
                                            <td className="px-4 py-3">
                                                <div className="flex items-center gap-3">
                                                    {file.is_dir ? <Folder className="w-5 h-5 text-yellow-500 fill-yellow-500/20" /> : file.is_encrypted ? <Lock className="w-5 h-5 text-secondary fill-secondary/20" /> : <File className="w-5 h-5 text-gray-400" />}
                                                    <span className="font-medium text-gray-900 dark:text-gray-200">{file.name}</span>
                                                </div>
                                            </td>
                                            <td className="px-4 py-3">
                                                {!file.is_dir && (
                                                    <button
                                                        onClick={(e) => { e.stopPropagation(); handleScanFile(file.path) }}
                                                        className="flex items-center gap-1 px-2 py-1 rounded bg-gray-100 dark:bg-dark-800 text-xs font-medium text-gray-600 dark:text-gray-300 hover:text-primary transition-colors"
                                                    >
                                                        <Shield className="w-3 h-3" />
                                                        Scan
                                                    </button>
                                                )}
                                            </td>
                                            <td className="px-4 py-3 text-gray-500 dark:text-gray-400">
                                                {file.is_dir ? '-' : formatBytes(file.size)}
                                            </td>
                                            <td className="px-4 py-3 text-gray-500 dark:text-gray-400">
                                                {file.is_encrypted ? 'Criptografado' : file.is_dir ? 'Pasta' : 'Arquivo'}
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>

                        {/* Mobile Card View (Visible on Mobile Only) */}
                        <div className="sm:hidden p-4">
                            {files.map((file: any) => (
                                <FileCard
                                    key={file.path}
                                    file={file}
                                    isSelected={selectedFiles.has(file.path)}
                                    onToggle={() => toggleFileSelection(file.path)}
                                    onClick={() => handleFileClick(file)}
                                />
                            ))}
                        </div>
                    </>
                )}
            </div>

            {/* Scan Modal */}
            <Modal
                isOpen={isScanModalOpen}
                onClose={() => setIsScanModalOpen(false)}
                title="Deep Integrity Report"
                size="lg"
            >
                {scanReport && <SecurityReport report={scanReport} />}
            </Modal>

            {/* Loading Overlay */}
            {isScanning && (
                <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center">
                    <div className="bg-white dark:bg-dark-800 p-6 rounded-xl shadow-2xl flex flex-col items-center">
                        <RefreshCw className="w-10 h-10 text-primary animate-spin mb-4" />
                        <h3 className="text-lg font-bold text-gray-900 dark:text-white">Analisando Arquivo...</h3>
                        <p className="text-sm text-gray-500">Calculando hashes e entropia</p>
                    </div>
                </div>
            )}
        </div>
    )
}
