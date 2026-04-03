import { create } from 'zustand'

export type ToastTone = 'success' | 'error' | 'info'

export interface ToastItem {
  id: string
  tone: ToastTone
  message: string
}

interface ToastState {
  items: ToastItem[]
  push: (tone: ToastTone, message: string) => void
  remove: (id: string) => void
}

export const useToastStore = create<ToastState>((set) => ({
  items: [],
  push: (tone, message) => {
    const id = `${Date.now()}-${Math.random().toString(16).slice(2)}`
    set((state) => ({ items: [...state.items, { id, tone, message }] }))
    setTimeout(() => {
      set((state) => ({ items: state.items.filter((item) => item.id !== id) }))
    }, 4000)
  },
  remove: (id) => set((state) => ({ items: state.items.filter((item) => item.id !== id) })),
}))
