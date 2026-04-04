interface SectionHeaderProps {
  number: string
  title: string
  description?: string
}

export function SectionHeader({ number, title, description }: SectionHeaderProps) {
  return (
    <div className="mb-12 space-y-4 max-w-3xl relative">
      {/* Decorative line */}
      <div className="absolute -left-6 top-0 bottom-0 w-1 bg-gradient-to-b from-cyan-400/50 via-green-400/30 to-transparent rounded-full" />

      <div className="space-y-2">
        <div className="flex items-center gap-2">
          <span className="text-sm font-mono text-cyan-400 tracking-widest">/</span>
          <span className="text-xs font-mono text-green-400 tracking-[0.3em]">{number}</span>
          <div className="hidden sm:flex flex-1 h-px bg-gradient-to-r from-green-400/30 to-transparent ml-2" />
        </div>
        <h2 className="text-4xl font-bold tracking-tight text-white font-display">
          {title}
        </h2>
        {description && (
          <p className="text-lg text-gray-400 leading-relaxed pt-2">{description}</p>
        )}
      </div>
    </div>
  )
}
