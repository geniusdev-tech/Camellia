import { create } from 'zustand'
import type { FileItem, Device } from '../api/types'

interface VaultState {
    currentPath: string
    currentDevice: string
    files: FileItem[]
    selectedFiles: Set<string>
    devices: Device[]

    // Process state
    currentTaskId: string | null
    processProgress: number
    processLogs: string[]

    // Actions
    setCurrentPath: (path: string) => void
    setCurrentDevice: (deviceId: string) => void
    setFiles: (files: FileItem[]) => void
    setDevices: (devices: Device[]) => void
    toggleFileSelection: (path: string) => void
    clearSelection: () => void
    selectAll: () => void

    // Process actions
    setCurrentTask: (taskId: string | null) => void
    setProcessProgress: (progress: number) => void
    addProcessLog: (log: string) => void
    clearProcessLogs: () => void
}

export const useVaultStore = create<VaultState>()((set, get) => ({
    currentPath: 'home',
    currentDevice: 'local',
    files: [],
    selectedFiles: new Set(),
    devices: [],
    currentTaskId: null,
    processProgress: 0,
    processLogs: [],

    setCurrentPath: (path) => set({ currentPath: path }),

    setCurrentDevice: (deviceId) => set({ currentDevice: deviceId }),

    setFiles: (files) => set({ files, selectedFiles: new Set() }),

    setDevices: (devices) => set({ devices }),

    toggleFileSelection: (path) =>
        set((state) => {
            const newSelection = new Set(state.selectedFiles)
            if (newSelection.has(path)) {
                newSelection.delete(path)
            } else {
                newSelection.add(path)
            }
            return { selectedFiles: newSelection }
        }),

    clearSelection: () => set({ selectedFiles: new Set() }),

    selectAll: () => {
        const allPaths = get().files.map((f) => f.path)
        set({ selectedFiles: new Set(allPaths) })
    },

    setCurrentTask: (taskId) =>
        set({
            currentTaskId: taskId,
            processProgress: 0,
            processLogs: taskId ? get().processLogs : [],
        }),

    setProcessProgress: (progress) => set({ processProgress: progress }),

    addProcessLog: (log) =>
        set((state) => ({
            processLogs: [...state.processLogs, log],
        })),

    clearProcessLogs: () => set({ processLogs: [] }),
}))
