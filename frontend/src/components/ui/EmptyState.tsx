'use client'

export function EmptyState({ title, text }: { title: string; text: string }) {
  return (
    <div className="rounded-2xl border border-dashed border-white/10 p-6 text-center">
      <div className="text-sm font-medium text-white">{title}</div>
      <div className="mt-2 text-sm text-gray-500">{text}</div>
    </div>
  )
}
