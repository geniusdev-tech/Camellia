import type { Metadata } from 'next'
import { Orbitron, Rajdhani, Share_Tech_Mono } from 'next/font/google'
import './globals.css'
import { Providers } from '@/components/providers'

const fontSans = Rajdhani({
  subsets: ['latin'],
  weight: ['400', '500', '600', '700'],
  variable: '--font-geist-sans',
  display: 'swap',
})

const fontMono = Share_Tech_Mono({
  subsets: ['latin'],
  weight: ['400'],
  variable: '--font-geist-mono',
  display: 'swap',
})

const fontDisplay = Orbitron({
  subsets: ['latin'],
  weight: ['500', '600', '700', '800'],
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
        <main>
          <Providers>{children}</Providers>
        </main>
      </body>
    </html>
  )
}
