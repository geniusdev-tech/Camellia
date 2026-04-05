'use client'

import { useEffect, useRef } from 'react'
import { AnimatePresence, motion } from 'framer-motion'
import { X } from 'lucide-react'

interface ModalProps {
  open: boolean
  title: string
  children: React.ReactNode
  onClose: () => void
  footer?: React.ReactNode
}

export function Modal({ open, title, children, onClose, footer }: ModalProps) {
  const closeButtonRef = useRef<HTMLButtonElement | null>(null)

  useEffect(() => {
    if (!open) return
    closeButtonRef.current?.focus()

    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') onClose()
    }

    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [open, onClose])

  return (
    <AnimatePresence>
      {open ? (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 backdrop-blur-md"
          onClick={onClose}
        >
          <motion.div
            initial={{ opacity: 0, y: 10, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 10, scale: 0.98 }}
            role="dialog"
            aria-modal="true"
            aria-label={title}
            className="glass w-full max-w-2xl rounded-2xl animate-border-glow"
            onClick={(event) => event.stopPropagation()}
          >
            <header className="flex items-center justify-between border-b border-white/[0.06] px-5 py-4">
              <h3 className="text-base font-semibold text-white">{title}</h3>
              <button
                ref={closeButtonRef}
                onClick={onClose}
                className="rounded-lg p-1 text-gray-500 transition-colors hover:bg-white/5 hover:text-white"
                aria-label="Fechar modal"
              >
                <X className="h-4 w-4" />
              </button>
            </header>

            <main className="max-h-[70vh] overflow-y-auto px-5 py-4">
              {children}
            </main>

            {footer && (
              <footer className="flex items-center justify-end gap-2 border-t border-white/[0.06] px-5 py-4">
                {footer}
              </footer>
            )}
          </motion.div>
        </motion.div>
      ) : null}
    </AnimatePresence>
  )
}
