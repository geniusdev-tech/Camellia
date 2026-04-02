import { create } from 'zustand'

interface VaultState {
  currentPath:   string
  currentDevice: string
  selectedFiles: Set<string>
  taskId:        string | null

  setCurrentPath:   (p: string) => void
  setCurrentDevice: (d: string) => void
  toggleFile:       (p: string) => void
  selectAll:        (paths: string[]) => void
  clearSelection:   () => void
  setTaskId:        (id: string | null) => void
}

export const useVaultStore = create<VaultState>()((set) => ({
  currentPath:   'home',
  currentDevice: 'local',
  selectedFiles: new Set<string>(),
  taskId:        null,

  setCurrentPath:   (currentPath) => set({ currentPath }),
  setCurrentDevice: (currentDevice) => set({ currentDevice }),

  toggleFile: (path) =>
    set((s) => {
      const next = new Set(s.selectedFiles)
      next.has(path) ? next.delete(path) : next.add(path)
      return { selectedFiles: next }
    }),

  selectAll: (paths) => set({ selectedFiles: new Set(paths) }),

  clearSelection: () => set({ selectedFiles: new Set() }),

  setTaskId: (taskId) => set({ taskId }),
}))
