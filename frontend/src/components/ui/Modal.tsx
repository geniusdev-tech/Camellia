import { ReactNode, useEffect } from 'react'
import { X } from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'
import { clsx } from 'clsx'

interface ModalProps {
    isOpen: boolean
    onClose: () => void
    title?: string
    children: ReactNode
    size?: 'sm' | 'md' | 'lg' | 'xl'
}

export default function Modal({
    isOpen,
    onClose,
    title,
    children,
    size = 'md',
}: ModalProps) {
    useEffect(() => {
        const handleEscape = (e: KeyboardEvent) => {
            if (e.key === 'Escape') onClose()
        }

        if (isOpen) {
            document.addEventListener('keydown', handleEscape)
            document.body.style.overflow = 'hidden'
        }

        return () => {
            document.removeEventListener('keydown', handleEscape)
            document.body.style.overflow = 'unset'
        }
    }, [isOpen, onClose])

    return (
        <AnimatePresence>
            {isOpen && (
                <>
                    {/* Backdrop */}
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        onClick={onClose}
                        className="fixed inset-0 bg-black/50 backdrop-blur-sm z-40"
                    />

                    {/* Modal */}
                    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
                        <motion.div
                            initial={{ opacity: 0, scale: 0.95, y: 20 }}
                            animate={{ opacity: 1, scale: 1, y: 0 }}
                            exit={{ opacity: 0, scale: 0.95, y: 20 }}
                            transition={{ duration: 0.2 }}
                            className={clsx(
                                'bg-white dark:bg-dark-800 rounded-xl shadow-2xl',
                                'max-h-[90vh] overflow-y-auto scrollbar-thin',
                                'w-full',
                                {
                                    'max-w-sm': size === 'sm',
                                    'max-w-md': size === 'md',
                                    'max-w-2xl': size === 'lg',
                                    'max-w-4xl': size === 'xl',
                                }
                            )}
                        >
                            {/* Header */}
                            {title && (
                                <div className="flex items-center justify-between px-6 py-4 border-b border-gray-200 dark:border-dark-700">
                                    <h2 className="text-xl font-semibold text-gray-900 dark:text-gray-100">
                                        {title}
                                    </h2>
                                    <button
                                        onClick={onClose}
                                        className="p-1 rounded-lg hover:bg-gray-100 dark:hover:bg-dark-700 transition-colors"
                                    >
                                        <X className="w-5 h-5" />
                                    </button>
                                </div>
                            )}

                            {/* Content */}
                            <div className="p-6">{children}</div>
                        </motion.div>
                    </div>
                </>
            )}
        </AnimatePresence>
    )
}
