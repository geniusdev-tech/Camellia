import React from 'react'

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'ghost' | 'terminal' | 'danger'
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
  const baseStyles = 'font-semibold rounded-xl transition-all duration-200 inline-flex items-center justify-center gap-2 relative active:scale-[0.97]'

  const sizeStyles = {
    sm: 'px-3 py-1.5 text-sm',
    md: 'px-5 py-2.5 text-sm',
    lg: 'px-8 py-3.5 text-base',
  }

  const variantStyles = {
    primary: 'bg-gradient-to-r from-green-400 to-emerald-500 text-dark-950 hover:shadow-lg hover:shadow-green-400/25',
    secondary: 'glass text-gray-300 hover:text-white hover:border-cyan-400/20',
    ghost: 'text-gray-400 hover:text-white hover:bg-white/5',
    terminal: 'glass-accent text-cyan-400 font-mono tracking-wide hover:border-cyan-400/30',
    danger: 'bg-red-500/10 border border-red-500/20 text-red-300 hover:bg-red-500/15 hover:border-red-500/30',
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
