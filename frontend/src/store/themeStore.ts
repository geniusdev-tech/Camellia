import { create } from 'zustand'
import { persist } from 'zustand/middleware'

interface ThemeState {
    theme: 'light' | 'dark'
    toggleTheme: () => void
    setTheme: (theme: 'light' | 'dark') => void
}

export const useThemeStore = create<ThemeState>()(
    persist(
        (set) => ({
            theme: 'dark',

            toggleTheme: () =>
                set((state) => {
                    const newTheme = state.theme === 'light' ? 'dark' : 'light'
                    updateDocumentTheme(newTheme)
                    return { theme: newTheme }
                }),

            setTheme: (theme) => {
                updateDocumentTheme(theme)
                set({ theme })
            },
        }),
        {
            name: 'camellia-theme',
            onRehydrateStorage: () => (state) => {
                if (state) {
                    updateDocumentTheme(state.theme)
                }
            },
        }
    )
)

function updateDocumentTheme(theme: 'light' | 'dark') {
    if (theme === 'dark') {
        document.documentElement.classList.add('dark')
    } else {
        document.documentElement.classList.remove('dark')
    }
}
