import type { Metadata } from 'next'
import './globals.css'
import { Providers } from '@/components/providers'

export const metadata: Metadata = {
  title: 'GateStack · Conformidade, Inteligência, Controle',
  description: 'Conformidade de acesso, inteligência de segurança e políticas em tempo real para squads DevSecOps',
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="pt-BR" className="dark scroll-smooth">
      <body className="min-h-screen antialiased bg-dark-950 text-white">
        <main>
          <Providers>{children}</Providers>
        </main>
      </body>
    </html>
  )
}
