import { InputHTMLAttributes, forwardRef } from 'react'
import { clsx } from 'clsx'

interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
    label?: string
    error?: string
}

const Input = forwardRef<HTMLInputElement, InputProps>(
    ({ className, label, error, type = 'text', ...props }, ref) => {
        return (
            <div className="w-full">
                {label && (
                    <label className="block text-sm font-medium mb-1.5 text-gray-700 dark:text-gray-300">
                        {label}
                    </label>
                )}
                <input
                    type={type}
                    ref={ref}
                    className={clsx(
                        'w-full px-3 py-2 rounded-lg border transition-colors',
                        'bg-white dark:bg-dark-800',
                        'text-gray-900 dark:text-gray-100',
                        'border-gray-300 dark:border-dark-600',
                        'placeholder:text-gray-400 dark:placeholder:text-gray-500',
                        'focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent',
                        'disabled:opacity-50 disabled:cursor-not-allowed',
                        error && 'border-danger focus:ring-danger',
                        className
                    )}
                    {...props}
                />
                {error && (
                    <p className="mt-1 text-sm text-danger">{error}</p>
                )}
            </div>
        )
    }
)

Input.displayName = 'Input'

export default Input
