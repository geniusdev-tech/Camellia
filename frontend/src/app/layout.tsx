import type { Metadata } from 'next'
import { IBM_Plex_Mono, Manrope, Space_Grotesk } from 'next/font/google'
import './globals.css'
import { Providers } from '@/components/providers'
import { NetworkGridWrapper } from '@/components/ui/NetworkGridWrapper'

const fontSans = Manrope({
  subsets: ['latin'],
  weight: ['400', '500', '600', '700', '800'],
  variable: '--font-geist-sans',
  display: 'swap',
})

const fontMono = IBM_Plex_Mono({
  subsets: ['latin'],
  weight: ['400', '500'],
  variable: '--font-geist-mono',
  display: 'swap',
})

const fontDisplay = Space_Grotesk({
  subsets: ['latin'],
  weight: ['500', '600', '700'],
  variable: '--font-display',
  display: 'swap',
})

export const metadata: Metadata = {
  title: 'GateStack · Conformidade, Inteligência, Controle',
  description: 'Conformidade de acesso, inteligência de segurança e políticas em tempo real para squads DevSecOps',
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="pt-BR" className={`dark scroll-smooth ${fontSans.variable} ${fontMono.variable} ${fontDisplay.variable}`}>
      <body className="min-h-screen antialiased bg-dark-950 text-white">
        <NetworkGridWrapper />
        <div className="relative z-10">
          <Providers>{children}</Providers>
        </div>
      </body>
    </html>
  )
}
