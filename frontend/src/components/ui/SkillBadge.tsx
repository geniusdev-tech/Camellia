interface SkillBadgeProps {
  name: string
  category: string
  proficiency: number
}

export function SkillBadge({ name, category, proficiency }: SkillBadgeProps) {
  const isHighProficiency = proficiency >= 85
  const glowColor = isHighProficiency ? 'from-green-400/50 via-cyan-400/30 to-transparent' : 'from-cyan-400/30 via-green-400/20 to-transparent'
  
  return (
    <div className="relative group">
      {/* Glow backdrop */}
      <div className={`absolute inset-0 rounded-lg bg-gradient-to-br ${glowColor} blur-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300`} />
      
      <div className="relative bg-dark-900/50 border border-green-400/30 group-hover:border-cyan-400/50 rounded-lg p-6 transition-all duration-300">
        <div className="flex justify-between items-start mb-4">
          <div>
            <h3 className="font-mono font-semibold text-white">{name}</h3>
            <p className="text-xs text-gray-500 tracking-wide">{category}</p>
          </div>
          <span className={`font-mono font-bold text-sm ${proficiency >= 85 ? 'text-green-400' : 'text-cyan-400'}`}>
            {proficiency}%
          </span>
        </div>
        
        {/* Progress bar with cyber effect */}
        <div className="w-full bg-dark-800 rounded-full h-1.5 overflow-hidden border border-white/5">
          <div 
            className={`h-1.5 rounded-full transition-all duration-500 ${
              proficiency >= 85 
                ? 'bg-gradient-to-r from-green-400 to-green-300 shadow-lg shadow-green-400/50' 
                : 'bg-gradient-to-r from-cyan-400 to-cyan-300 shadow-lg shadow-cyan-400/30'
            }`}
            style={{ width: `${proficiency}%` }}
          />
        </div>

        {/* Status indicator */}
        <div className="mt-3 text-[0.65rem] text-gray-500 font-mono flex justify-between">
          <span>PROFICIENCY</span>
          <span className={proficiency >= 85 ? 'text-green-400' : 'text-cyan-400'}>
            {proficiency >= 90 ? '◉ MASTER' : proficiency >= 85 ? '◐ EXPERT' : '◌ ADVANCED'}
          </span>
        </div>
      </div>
    </div>
  )
}
