'use client'
import { useState, useEffect, useCallback } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Lock, Unlock, Play, Square, Loader2,
  Terminal, ChevronDown, ChevronUp, CheckCircle2, AlertTriangle,
} from 'lucide-react'
import { vaultAPI } from '@/lib/api'
import { notify } from '@/lib/tauri'
import { useVaultStore } from '@/store/vault'

export function ProcessPanel() {
  const qc = useQueryClient()
  const { selectedFiles, currentDevice, setTaskId, taskId } = useVaultStore()
  const [encrypt, setEncrypt]     = useState(true)
  const [starting, setStarting]   = useState(false)
  const [error, setError]         = useState('')
  const [logsOpen, setLogsOpen]   = useState(false)
  const [allLogs, setAllLogs]     = useState<string[]>([])
  const [lastResult, setLastResult] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null)

  /* ── Poll task status ─────────────────────────── */
  const { data: status } = useQuery({
    queryKey:  ['taskStatus', taskId],
    queryFn:   () => vaultAPI.getProcessStatus(taskId!),
    enabled:   !!taskId,
    refetchInterval: 400,
  })

  useEffect(() => {
    if (!status) return
    if (status.logs?.length) {
      setAllLogs((prev) => {
        const set = new Set(prev)
        const fresh = status.logs.filter((l: string) => !set.has(l))
        return fresh.length ? [...prev, ...fresh] : prev
      })
    }
    if (status.done) {
      const wasSuccessful = status.status === 'Completed'
      const summary = wasSuccessful
        ? `${encrypt ? 'Criptografia' : 'Descriptografia'} concluida com sucesso.`
        : `Operacao finalizada com status: ${status.status}.`
      setLastResult({ kind: wasSuccessful ? 'ok' : 'err', text: summary })
      if (wasSuccessful) {
        notify('Camellia Shield', summary).catch(() => {})
      }
      setTaskId(null)
      useVaultStore.getState().clearSelection()
      qc.invalidateQueries({ queryKey: ['files'] })
      qc.invalidateQueries({ queryKey: ['files-home'] })
      qc.invalidateQueries({ queryKey: ['audit-events'] })
    }
  }, [status, setTaskId, qc, encrypt])

  const progress = status?.progress ?? 0
  const running  = !!taskId && !status?.done

  /* ── Start ───────────────────────────────────── */
  const start = useCallback(async () => {
    if (selectedFiles.size === 0) return
    setError('')
    setLastResult(null)
    setStarting(true)
    setAllLogs([])
    try {
      const res = await vaultAPI.batchProcess({
        targets: Array.from(selectedFiles),
        encrypt,
        recursive: true,
        device_id: currentDevice,
      })
      if (res.success && res.task_id) {
        setTaskId(res.task_id)
      } else {
        setError(res.msg || 'Erro ao iniciar')
      }
    } catch (e: unknown) {
      setError((e as Error).message)
    } finally {
      setStarting(false)
    }
  }, [selectedFiles, encrypt, currentDevice, setTaskId])

  const cancel = useCallback(async () => {
    if (!taskId) return
    await vaultAPI.cancelProcess(taskId).catch(() => {})
    setLastResult({ kind: 'err', text: 'Operacao cancelada.' })
    setTaskId(null)
  }, [taskId, setTaskId])

  const statusText = status?.status ?? 'Aguardando'

  return (
    <div className="glass rounded-2xl shadow-panel overflow-hidden">
      {/* Header */}
      <div className="px-5 py-4 border-b border-white/[0.05]">
        <h2 className="text-sm font-semibold text-white">Operação</h2>
        <p className="text-xs text-gray-500 mt-0.5">
          {selectedFiles.size
            ? `${selectedFiles.size} ${selectedFiles.size === 1 ? 'arquivo' : 'arquivos'} selecionado${selectedFiles.size !== 1 ? 's' : ''}`
            : 'Nenhum arquivo selecionado'}
        </p>
      </div>

      <div className="p-5 space-y-4">
        {/* Mode toggle */}
        <div className="flex p-1 bg-dark-850/80 rounded-xl gap-1">
          {([
            { value: true,  label: 'Criptografar', Icon: Lock },
            { value: false, label: 'Descriptografar', Icon: Unlock },
          ] as const).map(({ value, label, Icon }) => (
            <button
              key={label}
              disabled={running}
              onClick={() => setEncrypt(value)}
              className={`flex-1 flex items-center justify-center gap-2 py-2 rounded-lg text-xs font-medium transition-all ${
                encrypt === value
                  ? 'bg-dark-700 text-white shadow-sm'
                  : 'text-gray-500 hover:text-gray-300'
              }`}
            >
              <Icon className="w-3 h-3" />
              {label}
            </button>
          ))}
        </div>

        {/* Progress bar */}
        <AnimatePresence>
          {running && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="overflow-hidden"
            >
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs text-gray-400">
                  <span className="font-mono truncate">{statusText}</span>
                  <span className="font-mono shrink-0">{progress.toFixed(0)}%</span>
                </div>
                <div className="h-2 bg-dark-800 rounded-full overflow-hidden">
                  <motion.div
                    className="h-full bg-gradient-to-r from-primary-500 to-accent rounded-full"
                    animate={{ width: `${progress}%` }}
                    transition={{ type: 'spring', damping: 20 }}
                  />
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Error */}
        {error && (
          <p className="text-xs text-danger bg-danger/10 rounded-xl px-3 py-2 border border-danger/20">{error}</p>
        )}

        {lastResult && (
          <div
            className={`flex items-center gap-2 rounded-xl px-3 py-2 text-xs border ${
              lastResult.kind === 'ok'
                ? 'text-accent bg-accent/10 border-accent/20'
                : 'text-warning bg-warning/10 border-warning/20'
            }`}
          >
            {lastResult.kind === 'ok' ? <CheckCircle2 className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />}
            {lastResult.text}
          </div>
        )}

        {/* Action button */}
        <button
          onClick={running ? cancel : start}
          disabled={!running && (selectedFiles.size === 0 || starting)}
          className={`w-full flex items-center justify-center gap-2 py-2.5 rounded-xl font-semibold text-sm transition-all ${
            running
              ? 'bg-danger/20 hover:bg-danger/30 border border-danger/30 text-danger'
              : 'bg-gradient-to-r from-primary-600 to-accent-600 hover:opacity-90 text-white shadow-glow-primary disabled:opacity-40 disabled:cursor-not-allowed'
          }`}
        >
          {starting ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : running ? (
            <><Square className="w-4 h-4" /> Cancelar</>
          ) : (
            <><Play className="w-4 h-4" /> Executar</>
          )}
        </button>

        {/* Logs toggle */}
        {allLogs.length > 0 && (
          <div>
            <button
              onClick={() => setLogsOpen((v) => !v)}
              className="flex items-center gap-1.5 text-xs text-gray-500 hover:text-gray-300 transition-colors w-full"
            >
              <Terminal className="w-3 h-3" />
              Logs ({allLogs.length})
              {logsOpen ? <ChevronUp className="w-3 h-3 ml-auto" /> : <ChevronDown className="w-3 h-3 ml-auto" />}
            </button>

            <AnimatePresence>
              {logsOpen && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                  className="overflow-hidden mt-2"
                >
                  <div className="bg-dark-950 rounded-xl p-3 max-h-36 overflow-y-auto font-mono text-[10px] text-green-400 space-y-0.5">
                    {allLogs.slice(-30).map((l, i) => (
                      <div key={i} className="opacity-80">{l}</div>
                    ))}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        )}
      </div>
    </div>
  )
}
