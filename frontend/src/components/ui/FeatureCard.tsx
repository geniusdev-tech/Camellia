interface FeatureCardProps {
  title: string
  description: string
  icon?: React.ReactNode
  href?: string
}

export function FeatureCard({ title, description, icon, href }: FeatureCardProps) {
  const content = (
    <div className="space-y-4 relative">
      {/* Decorative corner elements */}
      <div className="absolute top-0 left-0 w-2 h-2 border-t-2 border-l-2 border-cyan-400/50" />
      <div className="absolute top-0 right-0 w-2 h-2 border-t-2 border-r-2 border-green-400/50" />
      <div className="absolute bottom-0 left-0 w-2 h-2 border-b-2 border-l-2 border-green-400/50" />
      <div className="absolute bottom-0 right-0 w-2 h-2 border-b-2 border-r-2 border-cyan-400/50" />

      {icon && <div className="text-4xl text-cyan-400">{icon}</div>}
      <div>
        <h3 className="text-lg font-semibold text-white mb-2 font-mono">{title}</h3>
        <p className="text-gray-400 text-sm leading-relaxed">{description}</p>
      </div>
    </div>
  )

  if (href) {
    return (
      <a 
        href={href}
        className="block bg-dark-900/40 border border-white/10 rounded-lg p-6 hover:border-cyan-400/50 hover:bg-dark-800/60 transition-all duration-300 group relative overflow-hidden"
      >
        {/* Hover glow effect */}
        <div className="absolute inset-0 bg-gradient-to-br from-cyan-400/0 to-green-400/0 group-hover:from-cyan-400/10 group-hover:to-green-400/10 transition-all duration-300" />
        <div className="relative">
          {content}
          <span className="text-cyan-400 text-sm mt-4 inline-block group-hover:translate-x-1 transition-transform font-mono">{">"} acessar</span>
        </div>
      </a>
    )
  }

  return (
    <div className="bg-dark-900/40 border border-white/10 rounded-lg p-6 hover:border-green-400/50 transition-colors relative overflow-hidden">
      <div className="absolute inset-0 bg-gradient-to-br from-green-400/0 to-transparent opacity-0 hover:opacity-10 transition-all duration-300" />
      <div className="relative">
        {content}
      </div>
    </div>
  )
}
