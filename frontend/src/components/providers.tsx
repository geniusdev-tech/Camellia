'use client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useRef } from 'react'

export function Providers({ children }: { children: React.ReactNode }) {
  const qcRef = useRef<QueryClient | null>(null)
  if (!qcRef.current) {
    qcRef.current = new QueryClient({
      defaultOptions: {
        queries: {
          retry: 1,
          staleTime: 30_000,
          refetchOnWindowFocus: false,
        },
      },
    })
  }

  return (
    <QueryClientProvider client={qcRef.current}>
      {children}
    </QueryClientProvider>
  )
}
