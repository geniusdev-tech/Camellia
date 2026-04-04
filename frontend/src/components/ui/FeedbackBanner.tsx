'use client'

import { AlertTriangle, CheckCircle2, Info } from 'lucide-react'

type Tone = 'success' | 'error' | 'info'

const toneClasses: Record<Tone, string> = {
  success: 'border-emerald-400/20 bg-emerald-400/10 text-emerald-200',
  error: 'border-rose-400/20 bg-rose-400/10 text-rose-200',
  info: 'border-sky-400/20 bg-sky-400/10 text-sky-200',
}

const IconMap = {
  success: CheckCircle2,
  error: AlertTriangle,
  info: Info,
} satisfies Record<Tone, React.ElementType>

export function FeedbackBanner({ tone, message }: { tone: Tone; message: string }) {
  const Icon = IconMap[tone]
  return (
    <div
      role="status"
      aria-live="polite"
      className={`flex items-start gap-2 rounded-xl border px-3 py-2 text-sm ${toneClasses[tone]}`}
    >
      <Icon className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
      <span>{message}</span>
    </div>
  )
}
