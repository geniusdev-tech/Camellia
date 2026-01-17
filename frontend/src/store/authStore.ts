import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import type { User } from '../api/types'

interface AuthState {
    user: User | null
    isAuthenticated: boolean
    requires2FA: boolean
    tempCredentials: { email: string } | null

    // Actions
    setUser: (user: User) => void
    setRequires2FA: (required: boolean, email?: string) => void
    logout: () => void
    clearTempCredentials: () => void
}

export const useAuthStore = create<AuthState>()(
    persist(
        (set) => ({
            user: null,
            isAuthenticated: false,
            requires2FA: false,
            tempCredentials: null,

            setUser: (user) =>
                set({
                    user,
                    isAuthenticated: true,
                    requires2FA: false,
                    tempCredentials: null,
                }),

            setRequires2FA: (required, email) =>
                set({
                    requires2FA: required,
                    tempCredentials: email ? { email } : null,
                }),

            logout: () =>
                set({
                    user: null,
                    isAuthenticated: false,
                    requires2FA: false,
                    tempCredentials: null,
                }),

            clearTempCredentials: () =>
                set({
                    requires2FA: false,
                    tempCredentials: null,
                }),
        }),
        {
            name: 'camellia-auth',
            partialize: (state) => ({
                user: state.user,
                isAuthenticated: state.isAuthenticated,
            }),
        }
    )
)
