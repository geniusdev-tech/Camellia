'use client'

import { useEffect, useRef } from 'react'

interface Node {
  x: number
  y: number
  vx: number
  vy: number
  size: number
  opacity: number
  pulsePhase: number
  pulseSpeed: number
}

const NODE_COUNT = 80
const CONNECTION_DISTANCE = 160
const MOUSE_RADIUS = 200
const BASE_SPEED = 0.15

export default function NetworkGrid() {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const nodesRef = useRef<Node[]>([])
  const mouseRef = useRef({ x: -9999, y: -9999 })
  const animRef = useRef<number>(0)
  const dprRef = useRef(1)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    const ctx = canvas.getContext('2d', { alpha: true })
    if (!ctx) return

    const dpr = Math.min(window.devicePixelRatio || 1, 2)
    dprRef.current = dpr

    function resize() {
      if (!canvas) return
      const w = window.innerWidth
      const h = window.innerHeight
      canvas.width = w * dprRef.current
      canvas.height = h * dprRef.current
      canvas.style.width = `${w}px`
      canvas.style.height = `${h}px`
    }

    function initNodes() {
      const w = window.innerWidth
      const h = window.innerHeight
      nodesRef.current = Array.from({ length: NODE_COUNT }, () => ({
        x: Math.random() * w,
        y: Math.random() * h,
        vx: (Math.random() - 0.5) * BASE_SPEED * 2,
        vy: (Math.random() - 0.5) * BASE_SPEED * 2,
        size: 2 + Math.random() * 3,
        opacity: 0.15 + Math.random() * 0.35,
        pulsePhase: Math.random() * Math.PI * 2,
        pulseSpeed: 0.005 + Math.random() * 0.015,
      }))
    }

    function animate() {
      if (!canvas || !ctx) return
      const w = window.innerWidth
      const h = window.innerHeight
      const d = dprRef.current

      ctx.clearRect(0, 0, canvas.width, canvas.height)
      ctx.save()
      ctx.scale(d, d)

      const mx = mouseRef.current.x
      const my = mouseRef.current.y
      const nodes = nodesRef.current

      // Update positions
      for (const node of nodes) {
        node.x += node.vx
        node.y += node.vy
        node.pulsePhase += node.pulseSpeed

        // Bounce off edges with padding
        if (node.x < -20) { node.x = -20; node.vx *= -1 }
        if (node.x > w + 20) { node.x = w + 20; node.vx *= -1 }
        if (node.y < -20) { node.y = -20; node.vy *= -1 }
        if (node.y > h + 20) { node.y = h + 20; node.vy *= -1 }
      }

      // Draw connections
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[i].x - nodes[j].x
          const dy = nodes[i].y - nodes[j].y
          const dist = Math.sqrt(dx * dx + dy * dy)

          if (dist < CONNECTION_DISTANCE) {
            const alpha = (1 - dist / CONNECTION_DISTANCE) * 0.18

            // Check if either node is near mouse
            const dmi = Math.sqrt((nodes[i].x - mx) ** 2 + (nodes[i].y - my) ** 2)
            const dmj = Math.sqrt((nodes[j].x - mx) ** 2 + (nodes[j].y - my) ** 2)
            const nearMouse = dmi < MOUSE_RADIUS || dmj < MOUSE_RADIUS
            const boost = nearMouse ? 2.5 : 1

            ctx.beginPath()
            ctx.moveTo(nodes[i].x, nodes[i].y)
            ctx.lineTo(nodes[j].x, nodes[j].y)
            ctx.strokeStyle = nearMouse
              ? `rgba(6, 182, 212, ${alpha * boost})`
              : `rgba(74, 222, 128, ${alpha * boost})`
            ctx.lineWidth = nearMouse ? 1.2 : 0.6
            ctx.stroke()
          }
        }
      }

      // Draw nodes (squares)
      for (const node of nodes) {
        const dm = Math.sqrt((node.x - mx) ** 2 + (node.y - my) ** 2)
        const nearMouse = dm < MOUSE_RADIUS
        const mouseInfluence = nearMouse ? 1 - dm / MOUSE_RADIUS : 0

        const pulse = Math.sin(node.pulsePhase) * 0.15
        const baseAlpha = node.opacity + pulse
        const alpha = baseAlpha + mouseInfluence * 0.5
        const size = node.size + mouseInfluence * 2.5

        // Glow for mouse-nearby nodes
        if (nearMouse) {
          ctx.shadowColor = 'rgba(6, 182, 212, 0.6)'
          ctx.shadowBlur = 12 * mouseInfluence
        } else {
          ctx.shadowColor = 'rgba(74, 222, 128, 0.3)'
          ctx.shadowBlur = 4
        }

        // Draw square node
        const half = size / 2
        ctx.beginPath()
        // Rounded square
        const r = size * 0.2
        ctx.moveTo(node.x - half + r, node.y - half)
        ctx.lineTo(node.x + half - r, node.y - half)
        ctx.quadraticCurveTo(node.x + half, node.y - half, node.x + half, node.y - half + r)
        ctx.lineTo(node.x + half, node.y + half - r)
        ctx.quadraticCurveTo(node.x + half, node.y + half, node.x + half - r, node.y + half)
        ctx.lineTo(node.x - half + r, node.y + half)
        ctx.quadraticCurveTo(node.x - half, node.y + half, node.x - half, node.y + half - r)
        ctx.lineTo(node.x - half, node.y - half + r)
        ctx.quadraticCurveTo(node.x - half, node.y - half, node.x - half + r, node.y - half)
        ctx.closePath()

        ctx.fillStyle = nearMouse
          ? `rgba(6, 182, 212, ${Math.min(alpha, 1)})`
          : `rgba(74, 222, 128, ${Math.min(alpha, 0.8)})`
        ctx.fill()

        // Border
        ctx.strokeStyle = nearMouse
          ? `rgba(6, 182, 212, ${Math.min(alpha * 0.7, 0.6)})`
          : `rgba(74, 222, 128, ${Math.min(alpha * 0.5, 0.4)})`
        ctx.lineWidth = 0.5
        ctx.stroke()

        ctx.shadowBlur = 0
      }

      ctx.restore()
      animRef.current = requestAnimationFrame(animate)
    }

    function handleMouseMove(e: MouseEvent) {
      mouseRef.current = { x: e.clientX, y: e.clientY }
    }

    function handleMouseLeave() {
      mouseRef.current = { x: -9999, y: -9999 }
    }

    resize()
    initNodes()
    animate()

    window.addEventListener('resize', resize)
    window.addEventListener('mousemove', handleMouseMove)
    document.addEventListener('mouseleave', handleMouseLeave)

    return () => {
      cancelAnimationFrame(animRef.current)
      window.removeEventListener('resize', resize)
      window.removeEventListener('mousemove', handleMouseMove)
      document.removeEventListener('mouseleave', handleMouseLeave)
    }
  }, [])

  return (
    <canvas
      ref={canvasRef}
      className="fixed inset-0 z-0 pointer-events-none"
      aria-hidden="true"
    />
  )
}
