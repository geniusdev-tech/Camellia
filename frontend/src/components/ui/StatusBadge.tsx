'use client'

export function statusBadgeClass(status: string) {
  switch (status) {
    case 'published':
    case 'completed':
      return 'border-emerald-400/20 bg-emerald-400/10 text-emerald-200'
    case 'approved':
    case 'running':
      return 'border-sky-400/20 bg-sky-400/10 text-sky-200'
    case 'submitted':
    case 'queued':
    case 'retry':
      return 'border-amber-400/20 bg-amber-400/10 text-amber-200'
    case 'rejected':
    case 'failed':
      return 'border-rose-400/20 bg-rose-400/10 text-rose-200'
    case 'archived':
      return 'border-gray-400/20 bg-gray-400/10 text-gray-300'
    default:
      return 'border-white/10 bg-white/5 text-gray-300'
  }
}

export function StatusBadge({ status }: { status: string }) {
  return (
    <span className={`rounded-full border px-2 py-1 text-[10px] font-medium ${statusBadgeClass(status)}`}>
      {status}
    </span>
  )
}
