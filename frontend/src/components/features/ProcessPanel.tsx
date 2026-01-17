import { useState, useEffect } from 'react'
import { Play, X, Lock, Unlock } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { motion, AnimatePresence } from 'framer-motion'
import { vaultAPI } from '../../api/client'
import { useVaultStore } from '../../store/vaultStore'
import Button from '../ui/Button'
import ProgressBar from '../ui/ProgressBar'

export default function ProcessPanel() {
    const {
        selectedFiles,
        currentDevice,
        currentTaskId,
        processProgress,
        processLogs,
        setCurrentTask,
        setProcessProgress,
        addProcessLog,
        clearSelection,
    } = useVaultStore()

    const [encrypt, setEncrypt] = useState(true)
    const [isStarting, setIsStarting] = useState(false)

    // Poll process status
    const { data: statusData } = useQuery({
        queryKey: ['processStatus', currentTaskId],
        queryFn: () => vaultAPI.getProcessStatus(currentTaskId!),
        enabled: !!currentTaskId,
        refetchInterval: 500, // Poll every 500ms
    })

    useEffect(() => {
        if (statusData) {
            setProcessProgress(statusData.progress)

            // Add new logs
            if (statusData.logs && statusData.logs.length > 0) {
                statusData.logs.slice(-5).forEach((log) => {
                    addProcessLog(log)
                })
            }

            // Task completed
            if (statusData.done) {
                setCurrentTask(null)
                clearSelection()
            }
        }
    }, [statusData, setProcessProgress, addProcessLog, setCurrentTask, clearSelection])

    const handleStartProcess = async () => {
        if (selectedFiles.size === 0) {
            alert('Selecione pelo menos um arquivo')
            return
        }

        setIsStarting(true)
        try {
            const targets = Array.from(selectedFiles)
            const response = await vaultAPI.batchProcess({
                targets,
                encrypt,
                recursive: true,
                device_id: currentDevice,
            })

            if (response.success && response.task_id) {
                setCurrentTask(response.task_id)
            } else {
                alert('Erro ao iniciar processo: ' + (response.msg || 'Erro desconhecido'))
            }
        } catch (error: any) {
            alert('Erro: ' + error.message)
        } finally {
            setIsStarting(false)
        }
    }

    const handleCancel = async () => {
        if (!currentTaskId) return

        try {
            await vaultAPI.cancelProcess(currentTaskId)
        } catch (error) {
            console.error('Cancel error:', error)
        }
    }

    const isProcessing = !!currentTaskId

    return (
        <div className="bg-white dark:bg-dark-800 rounded-xl shadow-lg p-6">
            {/* Header */}
            <div className="flex items-center justify-between mb-4">
                <div>
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                        Processamento
                    </h3>
                    <p className="text-sm text-gray-600 dark:text-gray-400">
                        {selectedFiles.size > 0
                            ? `${selectedFiles.size} ${selectedFiles.size === 1 ? 'item selecionado' : 'itens selecionados'}`
                            : 'Nenhum item selecionado'}
                    </p>
                </div>

                {/* Mode Toggle */}
                <div className="flex items-center gap-2 p-1 bg-gray-100 dark:bg-dark-700 rounded-lg">
                    <button
                        onClick={() => setEncrypt(true)}
                        disabled={isProcessing}
                        className={`px-4 py-2 rounded-md transition-all flex items-center gap-2 ${encrypt
                            ? 'bg-white dark:bg-dark-600 shadow-sm text-primary'
                            : 'text-gray-600 dark:text-gray-400'
                            }`}
                    >
                        <Lock className="w-4 h-4" />
                        Criptografar
                    </button>
                    <button
                        onClick={() => setEncrypt(false)}
                        disabled={isProcessing}
                        className={`px-4 py-2 rounded-md transition-all flex items-center gap-2 ${!encrypt
                            ? 'bg-white dark:bg-dark-600 shadow-sm text-secondary'
                            : 'text-gray-600 dark:text-gray-400'
                            }`}
                    >
                        <Unlock className="w-4 h-4" />
                        Descriptografar
                    </button>
                </div>
            </div>

            {/* Progress */}
            <AnimatePresence>
                {isProcessing && (
                    <motion.div
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: 'auto' }}
                        exit={{ opacity: 0, height: 0 }}
                        className="mb-4"
                    >
                        <ProgressBar
                            progress={processProgress}
                            color={encrypt ? 'primary' : 'secondary'}
                        />
                    </motion.div>
                )}
            </AnimatePresence>

            {/* Action Buttons */}
            <div className="flex gap-3">
                {!isProcessing ? (
                    <Button
                        onClick={handleStartProcess}
                        disabled={selectedFiles.size === 0}
                        isLoading={isStarting}
                        className="flex-1"
                    >
                        <Play className="w-4 h-4 mr-2" />
                        Executar
                    </Button>
                ) : (
                    <Button
                        onClick={handleCancel}
                        variant="danger"
                        className="flex-1"
                    >
                        <X className="w-4 h-4 mr-2" />
                        Cancelar
                    </Button>
                )}
            </div>

            {/* Logs */}
            <AnimatePresence>
                {processLogs.length > 0 && (
                    <motion.div
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: 'auto' }}
                        exit={{ opacity: 0, height: 0 }}
                        className="mt-4"
                    >
                        <div className="bg-gray-50 dark:bg-dark-900 rounded-lg p-3 max-h-32 overflow-y-auto scrollbar-thin">
                            {processLogs.slice(-10).map((log, index) => (
                                <div
                                    key={index}
                                    className="text-xs font-mono text-gray-600 dark:text-gray-400"
                                >
                                    {log}
                                </div>
                            ))}
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    )
}
