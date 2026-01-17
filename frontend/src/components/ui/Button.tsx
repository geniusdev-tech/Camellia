import { ButtonHTMLAttributes, forwardRef } from 'react'
import { clsx } from 'clsx'

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
    variant?: 'primary' | 'secondary' | 'danger' | 'ghost'
    size?: 'sm' | 'md' | 'lg'
    isLoading?: boolean
}

const Button = forwardRef<HTMLButtonElement, ButtonProps>(
    (
        {
            className,
            variant = 'primary',
            size = 'md',
            isLoading,
            disabled,
            children,
            ...props
        },
        ref
    ) => {
        return (
            <button
                ref={ref}
                disabled={disabled || isLoading}
                className={clsx(
                    'inline-flex items-center justify-center rounded-lg font-medium transition-all',
                    'focus:outline-none focus:ring-2 focus:ring-offset-2',
                    'disabled:opacity-50 disabled:cursor-not-allowed',
                    {
                        // Variants
                        'bg-primary hover:bg-primary-dark text-white focus:ring-primary':
                            variant === 'primary',
                        'bg-gray-200 dark:bg-dark-700 hover:bg-gray-300 dark:hover:bg-dark-600 text-gray-900 dark:text-gray-100 focus:ring-gray-400':
                            variant === 'secondary',
                        'bg-danger hover:bg-danger-dark text-white focus:ring-danger':
                            variant === 'danger',
                        'bg-transparent hover:bg-gray-100 dark:hover:bg-dark-800 text-gray-700 dark:text-gray-300':
                            variant === 'ghost',
                        // Sizes
                        'px-3 py-1.5 text-sm': size === 'sm',
                        'px-4 py-2 text-base': size === 'md',
                        'px-6 py-3 text-lg': size === 'lg',
                    },
                    className
                )}
                {...props}
            >
                {isLoading && (
                    <svg
                        className="animate-spin -ml-1 mr-2 h-4 w-4"
                        xmlns="http://www.w3.org/2000/svg"
                        fill="none"
                        viewBox="0 0 24 24"
                    >
                        <circle
                            className="opacity-25"
                            cx="12"
                            cy="12"
                            r="10"
                            stroke="currentColor"
                            strokeWidth="4"
                        />
                        <path
                            className="opacity-75"
                            fill="currentColor"
                            d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                        />
                    </svg>
                )}
                {children}
            </button>
        )
    }
)

Button.displayName = 'Button'

export default Button
