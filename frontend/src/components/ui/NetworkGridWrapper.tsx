'use client'

import dynamic from 'next/dynamic'

const NetworkGrid = dynamic(() => import('./NetworkGrid'), { ssr: false })

export function NetworkGridWrapper() {
  return <NetworkGrid />
}
