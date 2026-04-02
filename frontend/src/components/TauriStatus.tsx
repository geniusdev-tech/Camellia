'use client'
import { useEffect, useState } from 'react'
import { clsx } from 'clsx'

interface Props { className?: string }

export function TauriStatus({ className }: Props) {
  const [tauri, setTauri] = useState(false)
  const [version, setVersion] = useState<string | null>(null)

  useEffect(() => {
    const w = window as unknown as { __TAURI__?: unknown }
    if (w.__TAURI__) {
      setTauri(true)
      import('@tauri-apps/api/core')
        .then(({ invoke }) => invoke<string>('get_app_version'))
        .then(setVersion)
        .catch(() => {})
    }
  }, [])

  if (!tauri) return null

  return (
    <span
      title={`Tauri Desktop ${version ?? ''}`}
      className={clsx(
        'inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-accent/10 border border-accent/20 text-[10px] font-medium text-accent',
        className,
      )}
    >
      <span className="w-1.5 h-1.5 rounded-full bg-accent animate-pulse" />
      Desktop
    </span>
  )
}
