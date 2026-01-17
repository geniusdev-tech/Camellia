import { clsx } from 'clsx'

interface ProgressBarProps {
    progress: number // 0-100
    className?: string
    showLabel?: boolean
    color?: 'primary' | 'secondary' | 'danger'
}

export default function ProgressBar({
    progress,
    className,
    showLabel = true,
    color = 'primary',
}: ProgressBarProps) {
    const clampedProgress = Math.min(Math.max(progress, 0), 100)

    return (
        <div className={clsx('w-full', className)}>
            <div className="flex justify-between items-center mb-1.5">
                {showLabel && (
                    <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
                        {clampedProgress.toFixed(1)}%
                    </span>
                )}
            </div>
            <div className="w-full h-3 bg-gray-200 dark:bg-dark-700 rounded-full overflow-hidden">
                <div
                    className={clsx(
                        'h-full transition-all duration-300 ease-out rounded-full',
                        {
                            'bg-primary': color === 'primary',
                            'bg-secondary': color === 'secondary',
                            'bg-danger': color === 'danger',
                        }
                    )}
                    style={{ width: `${clampedProgress}%` }}
                />
            </div>
        </div>
    )
}
