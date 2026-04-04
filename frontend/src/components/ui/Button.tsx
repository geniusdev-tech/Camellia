import React from 'react'

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'ghost' | 'terminal'
  size?: 'sm' | 'md' | 'lg'
  children: React.ReactNode
  asLink?: boolean
  href?: string
}

export function Button({
  variant = 'primary',
  size = 'md',
  children,
  className,
  asLink,
  href,
  ...props
}: ButtonProps) {
  const baseStyles = 'font-semibold rounded transition-all duration-200 inline-flex items-center gap-2 relative'
  
  const sizeStyles = {
    sm: 'px-3 py-1.5 text-sm',
    md: 'px-6 py-2.5 text-base',
    lg: 'px-8 py-3 text-lg',
  }

  const variantStyles = {
    primary: 'bg-green-400 text-dark-950 hover:bg-green-300 hover:shadow-lg hover:shadow-green-400/50 active:scale-95',
    secondary: 'border border-green-400/50 text-green-400 hover:border-green-400 hover:bg-green-400/10 hover:shadow-lg hover:shadow-green-400/30',
    ghost: 'text-gray-300 hover:text-white hover:bg-white/5',
    terminal: 'border border-cyan-400/50 text-cyan-400 hover:border-cyan-400 hover:bg-cyan-400/10 hover:shadow-lg hover:shadow-cyan-400/30 font-mono tracking-wide',
  }

  const combined = `${baseStyles} ${sizeStyles[size]} ${variantStyles[variant]} ${className || ''}`

  if (asLink && href) {
    return (
      <a href={href} className={combined}>
        {children}
      </a>
    )
  }

  return (
    <button className={combined} {...props}>
      {children}
    </button>
  )
}
