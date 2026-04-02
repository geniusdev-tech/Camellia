'use client'
import { useQuery } from '@tanstack/react-query'
import { Shield, Lock, HardDrive, Zap } from 'lucide-react'
import { vaultAPI } from '@/lib/api'

function Stat({ icon: Icon, label, value, sub, accent = false }: {
  icon: React.ElementType; label: string; value: string; sub?: string; accent?: boolean
}) {
  return (
    <div className="glass rounded-2xl px-5 py-4 flex items-center gap-4 shadow-panel">
      <div className={`w-10 h-10 rounded-xl flex items-center justify-center shrink-0 ${accent ? 'bg-accent/15 text-accent' : 'bg-primary-600/15 text-primary-400'}`}>
        <Icon className="w-5 h-5" />
      </div>
      <div>
        <p className="text-xs text-gray-500 font-medium">{label}</p>
        <p className="text-lg font-bold text-white leading-tight">{value}</p>
        {sub && <p className="text-[10px] text-gray-600 mt-0.5">{sub}</p>}
      </div>
    </div>
  )
}

export function StatsBar() {
  const { data } = useQuery({
    queryKey: ['files-home'],
    queryFn: () => vaultAPI.listFiles({ path: 'home' }),
    staleTime: 30_000,
  })

  const total     = data?.items?.length ?? 0
  const encrypted = data?.items?.filter((f: { is_encrypted: boolean }) => f.is_encrypted).length ?? 0
  const plain = Math.max(total - encrypted, 0)
  const protectedRate = total ? `${Math.round((encrypted / total) * 100)}%` : '0%'
  const currentScope = data?.current_path === '/home/zeus' ? 'Home local' : (data?.current_path ?? 'Escopo atual')

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
      <Stat icon={Lock} label="Arquivos Cifrados" value={String(encrypted)} sub={`${protectedRate} do total visivel`} accent />
      <Stat icon={HardDrive} label="Arquivos Visiveis" value={String(total)} sub={`${plain} ainda sem cifra`} />
      <Stat icon={Shield} label="Status do Cofre" value="Ativo" sub={currentScope} accent />
      <Stat icon={Zap} label="Pipeline" value="Online" sub="Argon2id + Fernet dev" />
    </div>
  )
}
