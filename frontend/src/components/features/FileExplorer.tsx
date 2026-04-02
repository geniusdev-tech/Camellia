'use client'
import { useState, useCallback, useEffect } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Folder, File, Lock, Shield, RefreshCw, ChevronUp,
  HardDrive, Usb, Smartphone, CheckSquare, Square,
  Trash2, Edit3, ScanSearch, AlertTriangle, CheckCircle, CircleDashed,
} from 'lucide-react'
import { clsx } from 'clsx'
import { vaultAPI, deviceAPI } from '@/lib/api'
import { getCachedScan, invalidateCachedScan, moveCachedScan, setCachedScan } from '@/lib/scan-cache'
import { useVaultStore } from '@/store/vault'
import type { FileItem, ScanFileResponse } from '@/lib/types'

function fmt(bytes: number) {
  if (!bytes) return '0 B'
  const k = 1024, s = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${(bytes / k ** i).toFixed(1)} ${s[i]}`
}

function DeviceIcon({ type }: { type: string }) {
  if (type === 'usb')  return <Usb className="w-3.5 h-3.5" />
  if (type === 'mtp')  return <Smartphone className="w-3.5 h-3.5" />
  return <HardDrive className="w-3.5 h-3.5" />
}

function fileHealth(file: FileItem, scan?: ScanFileResponse | null) {
  if (file.is_dir) {
    return { label: 'Diretorio', tone: 'text-gray-500 bg-dark-800 border-white/[0.06]', Icon: Folder }
  }
  if (file.is_encrypted) {
    return { label: 'Protegido', tone: 'text-accent bg-accent/10 border-accent/20', Icon: Lock }
  }
  if (scan?.risk_analysis?.level === 'CRITICAL' || scan?.risk_analysis?.level === 'HIGH') {
    return { label: 'Suspeito', tone: 'text-warning bg-warning/10 border-warning/20', Icon: AlertTriangle }
  }
  if (scan?.risk_analysis?.level === 'LOW') {
    return { label: 'Verificado', tone: 'text-primary-300 bg-primary-600/10 border-primary-500/20', Icon: CheckCircle }
  }
  if (/\.(exe|dll|bat|sh|bin|msi|appimage)$/i.test(file.name)) {
    return { label: 'Nao verificado', tone: 'text-warning bg-warning/10 border-warning/20', Icon: AlertTriangle }
  }
  return { label: 'Normal', tone: 'text-gray-400 bg-dark-800 border-white/[0.06]', Icon: CircleDashed }
}

export function FileExplorer() {
  const qc = useQueryClient()
  const {
    currentPath, currentDevice,
    selectedFiles, setCurrentPath, setCurrentDevice,
    toggleFile, clearSelection, selectAll,
  } = useVaultStore()

  const [scanReport, setScanReport] = useState<ScanFileResponse | null>(null)
  const [scanning, setScanning]     = useState(false)
  const [renaming, setRenaming]     = useState<FileItem | null>(null)
  const [newName, setNewName]       = useState('')

  /* ── Devices ─────────────────────────────────── */
  const { data: deviceData } = useQuery({
    queryKey: ['devices'],
    queryFn:  deviceAPI.listDevices,
    refetchInterval: 5_000,
  })
  const devices = deviceData?.devices ?? []
  const userHomeDevice = devices.find((device) => device.id === 'system:user-home')
  const systemDevices = devices.filter((device) => device.id.startsWith('system:'))
  const userShortcuts = ['Documentos', 'Downloads', 'Imagens']
    .map((name) => {
      const base = userHomeDevice?.path
      return base ? { name, path: `${base}/${name}` } : null
    })
    .filter((item): item is { name: string; path: string } => Boolean(item))

  useEffect(() => {
    if (!userHomeDevice) return
    if (currentDevice === 'local' || currentPath === 'home') {
      setCurrentDevice(userHomeDevice.id)
      setCurrentPath(userHomeDevice.path)
    }
  }, [currentDevice, currentPath, setCurrentDevice, setCurrentPath, userHomeDevice])

  /* ── Files ───────────────────────────────────── */
  const { data, isFetching, error } = useQuery({
    queryKey:  ['files', currentPath, currentDevice],
    queryFn:   () => vaultAPI.listFiles({ path: currentPath, device_id: currentDevice }),
    refetchInterval: 6_000,
  })
  const files: FileItem[] = data?.items ?? []

  const refresh = () => qc.invalidateQueries({ queryKey: ['files'] })

  const goUp = () => {
    const parent = data?.parent_path
    if (parent) { setCurrentPath(parent); clearSelection() }
  }

  /* ── Actions ─────────────────────────────────── */
  const handleScan = useCallback(async (path: string) => {
    setScanning(true)
    try {
      const file = files.find((item) => item.path === path)
      const r = await vaultAPI.scanFile(path) as ScanFileResponse
      qc.setQueryData(['scan', path], r)
      if (file) setCachedScan(file, r)
      setScanReport(r)
    } finally { setScanning(false) }
  }, [files, qc])

  const handleDelete = useCallback(async (item: FileItem) => {
    if (!confirm(`Deletar "${item.name}"? Esta ação é irreversível.`)) return
    await vaultAPI.fileAction({ action: 'delete', path: item.path })
    qc.removeQueries({ queryKey: ['scan', item.path] })
    invalidateCachedScan(item.path)
    clearSelection(); refresh()
  }, [clearSelection, qc, refresh])

  const handleRename = useCallback(async () => {
    if (!renaming || !newName.trim()) return
    const nextFile: FileItem = {
      ...renaming,
      name: newName.trim(),
      path: `${renaming.path.slice(0, renaming.path.lastIndexOf('/') + 1)}${newName.trim()}`,
    }
    await vaultAPI.fileAction({ action: 'rename', path: renaming.path, new_name: newName.trim() })
    const previousScan = qc.getQueryData<ScanFileResponse>(['scan', renaming.path])
    qc.removeQueries({ queryKey: ['scan', renaming.path] })
    invalidateCachedScan(renaming.path)
    if (previousScan) {
      qc.setQueryData(['scan', nextFile.path], previousScan)
      moveCachedScan(renaming.path, nextFile)
    }
    setRenaming(null); setNewName(''); refresh()
  }, [newName, qc, refresh, renaming])

  const allSelected = files.length > 0 && files.every((f) => selectedFiles.has(f.path))

  /* ── Scan Report Modal ───────────────────────── */
  const riskColor = scanReport
    ? { LOW: 'text-accent', HIGH: 'text-warning', CRITICAL: 'text-danger' }[
        (scanReport.risk_analysis as { level: string })?.level
      ] ?? 'text-white'
    : 'text-white'

  return (
    <div className="flex flex-col gap-3">
      {systemDevices.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
          {systemDevices.map((device) => (
            <button
              key={device.id}
              onClick={() => { setCurrentDevice(device.id); setCurrentPath(device.path); clearSelection() }}
              className={clsx(
                'glass rounded-2xl border px-4 py-3 text-left transition-all',
                currentDevice === device.id
                  ? 'border-primary-500/30 bg-primary-600/10'
                  : 'border-white/[0.06] hover:border-white/[0.12] hover:bg-dark-800/60',
              )}
            >
              <div className="flex items-center gap-2 mb-1.5">
                <HardDrive className={clsx('w-4 h-4', currentDevice === device.id ? 'text-primary-300' : 'text-gray-500')} />
                <span className="text-sm font-semibold text-white">{device.name}</span>
              </div>
              <p className="text-[11px] text-gray-500 font-mono truncate">{device.path}</p>
            </button>
          ))}
        </div>
      )}

      {userHomeDevice && data?.current_path === userHomeDevice.path && (
        <div className="flex flex-wrap gap-2">
          {userShortcuts.map((shortcut) => (
            <button
              key={shortcut.path}
              onClick={() => { setCurrentPath(shortcut.path); clearSelection() }}
              className="rounded-full border border-white/[0.08] bg-dark-800 px-3 py-1.5 text-xs text-gray-300 hover:text-white hover:border-white/[0.16] transition-all"
            >
              {shortcut.name}
            </button>
          ))}
        </div>
      )}

      {/* ── Device Tabs ── */}
      <div className="flex gap-2 overflow-x-auto no-scrollbar">
        <button
          onClick={() => {
            setCurrentDevice(userHomeDevice?.id ?? 'local')
            setCurrentPath(userHomeDevice?.path ?? 'home')
            clearSelection()
          }}
          className={clsx(
            'flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-medium whitespace-nowrap transition-all border',
            currentDevice === (userHomeDevice?.id ?? 'local')
              ? 'bg-primary-600/20 border-primary-500/30 text-primary-300'
              : 'bg-dark-800 border-white/[0.06] text-gray-400 hover:text-white',
          )}
        >
          <HardDrive className="w-3 h-3" /> {userHomeDevice?.name ?? 'Usuario'}
        </button>
        {devices.filter((device) => device.id !== 'system:user-home').map((d) => (
          <button
            key={d.id}
            onClick={() => { setCurrentDevice(d.id); setCurrentPath(d.path); clearSelection() }}
            className={clsx(
              'flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-medium whitespace-nowrap transition-all border',
              currentDevice === d.id
                ? 'bg-primary-600/20 border-primary-500/30 text-primary-300'
                : 'bg-dark-800 border-white/[0.06] text-gray-400 hover:text-white',
            )}
          >
            <DeviceIcon type={d.type} /> {d.name}
          </button>
        ))}
      </div>

      {/* ── Explorer Card ── */}
      <div className="glass rounded-2xl shadow-panel overflow-hidden">
        {/* Toolbar */}
        <div className="flex items-center gap-2 px-4 py-2.5 border-b border-white/[0.05] bg-dark-850/60">
          <button onClick={goUp} disabled={!data?.parent_path} className="p-1.5 rounded-lg hover:bg-dark-700 text-gray-400 hover:text-white transition-all disabled:opacity-30">
            <ChevronUp className="w-4 h-4" />
          </button>
          <button onClick={refresh} className="p-1.5 rounded-lg hover:bg-dark-700 text-gray-400 hover:text-white transition-all">
            <RefreshCw className={clsx('w-4 h-4', isFetching && 'animate-spin')} />
          </button>

          <span className="flex-1 text-xs text-gray-500 font-mono truncate px-2" dir="rtl">
            {data?.current_path ?? currentPath}
          </span>

          {files.length > 0 && (
            <button
              onClick={() => allSelected ? clearSelection() : selectAll(files.map((f) => f.path))}
              className="p-1.5 rounded-lg hover:bg-dark-700 text-gray-400 hover:text-white transition-all"
            >
              {allSelected ? <CheckSquare className="w-4 h-4 text-accent" /> : <Square className="w-4 h-4" />}
            </button>
          )}
        </div>

        {/* Selection bar */}
        <AnimatePresence>
          {selectedFiles.size > 0 && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              className="overflow-hidden"
            >
              <div className="flex items-center gap-2 px-4 py-2 bg-primary-600/10 border-b border-primary-500/20 text-xs text-primary-300">
                <CheckSquare className="w-3.5 h-3.5" />
                <span>{selectedFiles.size} {selectedFiles.size === 1 ? 'item selecionado' : 'itens selecionados'}</span>
                <button onClick={clearSelection} className="ml-auto text-gray-500 hover:text-white transition-colors">
                  Limpar
                </button>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Error */}
        {error && (
          <div className="flex items-center gap-2 px-4 py-3 text-sm text-danger bg-danger/10 border-b border-danger/20">
            <AlertTriangle className="w-4 h-4" />
            {(error as Error).message}
          </div>
        )}

        {/* File list */}
        <div className="divide-y divide-white/[0.04] min-h-[300px] max-h-[520px] overflow-y-auto">
          {!isFetching && files.length === 0 && (
            <div className="flex flex-col items-center justify-center py-16 text-gray-600">
              <Folder className="w-10 h-10 mb-2 opacity-30" />
              <p className="text-sm">Pasta vazia</p>
            </div>
          )}

          {files.map((file) => {
            const selected = selectedFiles.has(file.path)
            const cachedScan = qc.getQueryData<ScanFileResponse>(['scan', file.path]) ?? getCachedScan(file)
            const health = fileHealth(file, cachedScan)
            return (
              <div
                key={file.path}
                className={clsx(
                  'group flex items-center gap-3 px-4 py-3 cursor-pointer transition-colors',
                  selected ? 'bg-primary-600/10' : 'hover:bg-dark-800/50',
                )}
                onClick={() => {
                  if (file.is_dir) { setCurrentPath(file.path); clearSelection() }
                  else toggleFile(file.path)
                }}
              >
                {/* Checkbox */}
                <div onClick={(e) => { e.stopPropagation(); toggleFile(file.path) }} className="shrink-0">
                  {selected
                    ? <CheckSquare className="w-4 h-4 text-accent" />
                    : <Square className="w-4 h-4 text-gray-600 group-hover:text-gray-400 transition-colors" />
                  }
                </div>

                {/* Icon */}
                <div className="shrink-0 w-8 h-8 rounded-xl flex items-center justify-center bg-dark-800">
                  {file.is_dir
                    ? <Folder className="w-4 h-4 text-yellow-400" />
                    : file.is_encrypted
                      ? <Lock className="w-4 h-4 text-accent" />
                      : <File className="w-4 h-4 text-gray-400" />
                  }
                </div>

                {/* Name + meta */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 min-w-0">
                    <p className="text-sm text-white font-medium truncate">{file.name}</p>
                    <span
                      className={clsx(
                        'inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-medium shrink-0',
                        health.tone,
                      )}
                    >
                      <health.Icon className="w-3 h-3" />
                      {health.label}
                    </span>
                  </div>
                  <p className="text-xs text-gray-600 mt-0.5">
                    {file.is_dir
                      ? 'Pasta'
                      : file.is_encrypted
                        ? `Criptografado · ${fmt(file.size)}`
                        : cachedScan?.risk_analysis?.level
                          ? `${health.label} · ${fmt(file.size)}`
                          : fmt(file.size)}
                  </p>
                </div>

                {/* Actions (appear on hover) */}
                {!file.is_dir && (
                  <div
                    className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <button
                      onClick={() => handleScan(file.path)}
                      title="Inspecionar integridade"
                      className="p-1.5 rounded-lg hover:bg-dark-700 text-gray-500 hover:text-accent transition-all"
                    >
                      <Shield className="w-3.5 h-3.5" />
                    </button>
                    <button
                      onClick={() => { setRenaming(file); setNewName(file.name) }}
                      title="Renomear"
                      className="p-1.5 rounded-lg hover:bg-dark-700 text-gray-500 hover:text-white transition-all"
                    >
                      <Edit3 className="w-3.5 h-3.5" />
                    </button>
                    <button
                      onClick={() => handleDelete(file)}
                      title="Deletar"
                      className="p-1.5 rounded-lg hover:bg-danger/20 text-gray-500 hover:text-danger transition-all"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>

      {/* ── Rename Modal ── */}
      <AnimatePresence>
        {renaming && (
          <motion.div
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4"
            onClick={() => setRenaming(null)}
          >
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.95, opacity: 0 }}
              className="glass rounded-2xl p-6 w-full max-w-sm shadow-panel"
              onClick={(e) => e.stopPropagation()}
            >
              <h3 className="text-base font-semibold text-white mb-4 flex items-center gap-2">
                <Edit3 className="w-4 h-4 text-gray-400" /> Renomear
              </h3>
              <input
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleRename()}
                className="w-full bg-dark-850 border border-white/10 rounded-xl px-4 py-2.5 text-sm text-white focus:outline-none focus:border-accent/50 mb-4"
                autoFocus
              />
              <div className="flex gap-2">
                <button onClick={() => setRenaming(null)} className="flex-1 py-2 rounded-xl bg-dark-700 text-sm text-gray-400 hover:text-white transition-all">Cancelar</button>
                <button onClick={handleRename} className="flex-1 py-2 rounded-xl bg-accent text-dark-900 font-semibold text-sm hover:bg-accent-300 transition-all">Renomear</button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* ── Scan Report Modal ── */}
      <AnimatePresence>
        {(scanning || scanReport) && (
          <motion.div
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4"
            onClick={() => setScanReport(null)}
          >
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.95, opacity: 0 }}
              className="glass rounded-2xl p-6 w-full max-w-lg shadow-panel"
              onClick={(e) => e.stopPropagation()}
            >
              {scanning ? (
                <div className="flex flex-col items-center py-8 gap-4">
                  <ScanSearch className="w-10 h-10 text-accent animate-pulse" />
                  <p className="text-sm text-gray-400">Analisando integridade do arquivo…</p>
                </div>
              ) : scanReport ? (
                <>
                  <div className="flex items-center justify-between mb-5">
                    <h3 className="text-base font-semibold text-white flex items-center gap-2">
                      <Shield className="w-4 h-4 text-gray-400" /> Deep Integrity Report
                    </h3>
                    <button onClick={() => setScanReport(null)} className="text-gray-500 hover:text-white text-xl leading-none">&times;</button>
                  </div>

                  <div className={clsx('flex items-center gap-3 p-4 rounded-xl border mb-4',
                    (scanReport.risk_analysis as {level:string})?.level === 'LOW'
                      ? 'bg-accent/10 border-accent/20'
                      : (scanReport.risk_analysis as {level:string})?.level === 'HIGH'
                        ? 'bg-warning/10 border-warning/20'
                        : 'bg-danger/10 border-danger/20',
                  )}>
                    {(scanReport.risk_analysis as {level:string})?.level === 'LOW'
                      ? <CheckCircle className={clsx('w-6 h-6', riskColor)} />
                      : <AlertTriangle className={clsx('w-6 h-6', riskColor)} />
                    }
                    <div>
                      <p className={clsx('font-bold', riskColor)}>
                        Risco: {(scanReport.risk_analysis as {level:string})?.level}
                      </p>
                      <p className="text-xs text-gray-500 mt-0.5">
                        {String((scanReport.risk_analysis as {notes?:string})?.notes || 'Nenhum fator de risco encontrado.')}
                      </p>
                    </div>
                  </div>

                  <div className="space-y-2 text-xs">
                    {[
                      ['SHA-256', (scanReport.hashes as {sha256:string})?.sha256],
                      ['BLAKE2b', (scanReport.hashes as {blake2b:string})?.blake2b],
                      ['Entropia', String((scanReport.risk_analysis as {entropy:number})?.entropy ?? '-')],
                      ['Tamanho', String((scanReport as {size?:number})?.size ?? '-')],
                    ].map(([k, v]) => (
                      <div key={k} className="flex justify-between gap-4 py-2 border-b border-white/[0.04]">
                        <span className="text-gray-500 shrink-0">{k}</span>
                        <span className="text-white font-mono truncate text-right">{v}</span>
                      </div>
                    ))}
                  </div>
                </>
              ) : null}
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
