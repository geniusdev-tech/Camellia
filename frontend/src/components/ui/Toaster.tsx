'use client'

import { useToastStore } from '@/store/toast'
import { FeedbackBanner } from './FeedbackBanner'

export function Toaster() {
  const items = useToastStore((state) => state.items)
  const remove = useToastStore((state) => state.remove)

  return (
    <section
      aria-live="polite"
      aria-atomic="true"
      className="pointer-events-none fixed right-4 top-4 z-[70] flex w-full max-w-sm flex-col gap-2"
    >
      {items.map((item) => (
        <button
          key={item.id}
          onClick={() => remove(item.id)}
          className="pointer-events-auto text-left"
          aria-label={`Dismiss notification: ${item.message}`}
        >
          <FeedbackBanner tone={item.tone} message={item.message} />
        </button>
      ))}
    </section>
  )
}
