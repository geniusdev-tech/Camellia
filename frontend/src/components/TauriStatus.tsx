'use client'
import { useEffect, useState } from 'react'
import { clsx } from 'clsx'

interface Props { className?: string }
interface DesktopRuntimeStatus {
  ready: boolean
  message?: string | null
  logPath: string
}

export function TauriStatus({ className }: Props) {
  const [tauri, setTauri] = useState(false)
  const [version, setVersion] = useState<string | null>(null)
  const [runtime, setRuntime] = useState<DesktopRuntimeStatus | null>(null)

  useEffect(() => {
    const w = window as unknown as { __TAURI__?: unknown }
    if (w.__TAURI__) {
      setTauri(true)
      import('@tauri-apps/api/core')
        .then(async ({ invoke }) => {
          const [appVersion, runtimeStatus] = await Promise.all([
            invoke<string>('get_app_version'),
            invoke<DesktopRuntimeStatus>('get_desktop_runtime_status'),
          ])
          setVersion(appVersion)
          setRuntime(runtimeStatus)
        })
        .catch(() => {})
    }
  }, [])

  if (!tauri) return null

  const degraded = runtime ? !runtime.ready || !!runtime.message : false
  const title = degraded
    ? `Desktop com falha: ${runtime?.message || 'Erro de inicialização'} | log: ${runtime?.logPath || 'indisponível'}`
    : `Tauri Desktop ${version ?? ''}`.trim()

  return (
    <span
      title={title}
      className={clsx(
        degraded
          ? 'inline-flex items-center gap-1 rounded-full border border-amber-400/40 bg-amber-400/10 px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider text-amber-200'
          : 'inline-flex items-center gap-1 rounded-full border border-cyan-400/40 bg-cyan-400/10 px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider text-cyan-300',
        className,
      )}
    >
      <span className={clsx('h-1.5 w-1.5 rounded-full animate-pulse', degraded ? 'bg-amber-300' : 'bg-cyan-300')} />
      {degraded ? 'Desktop com falha' : 'Desktop'}
    </span>
  )
}
