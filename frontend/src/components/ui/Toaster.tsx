'use client'

import { useToastStore } from '@/store/toast'
import { FeedbackBanner } from './FeedbackBanner'

export function Toaster() {
  const items = useToastStore((state) => state.items)
  const remove = useToastStore((state) => state.remove)

  return (
    <div className="pointer-events-none fixed right-4 top-4 z-[70] flex w-full max-w-sm flex-col gap-2">
      {items.map((item) => (
        <button
          key={item.id}
          onClick={() => remove(item.id)}
          className="pointer-events-auto text-left"
        >
          <FeedbackBanner tone={item.tone} message={item.message} />
        </button>
      ))}
    </div>
  )
}
