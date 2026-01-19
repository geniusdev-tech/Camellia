import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import type { User } from '../api/types'

interface AuthState {
    user: User | null
    isAuthenticated: boolean
    requires2FA: boolean
    accessToken: string | null
    tempCredentials: { email: string; userId?: number | string } | null

    // Actions
    setUser: (user: User, accessToken: string) => void
    setRequires2FA: (required: boolean, email?: string, userId?: number | string) => void
    logout: () => void
    clearTempCredentials: () => void
}

export const useAuthStore = create<AuthState>()(
    persist(
        (set) => ({
            user: null,
            isAuthenticated: false,
            requires2FA: false,
            accessToken: null,
            tempCredentials: null,

            setUser: (user, accessToken) =>
                set({
                    user,
                    accessToken,
                    isAuthenticated: true,
                    requires2FA: false,
                    tempCredentials: null,
                }),

            setRequires2FA: (required, email, userId) =>
                set({
                    requires2FA: required,
                    tempCredentials: email ? { email, userId } : null,
                }),

            logout: () =>
                set({
                    user: null,
                    isAuthenticated: false,
                    requires2FA: false,
                    accessToken: null,
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
