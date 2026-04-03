import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import type { AuthUser } from '@/lib/types'

interface AuthState {
  user: AuthUser | null
  accessToken: string | null
  refreshToken: string | null
  isAuthenticated: boolean

  setSession: (user: AuthUser, accessToken: string, refreshToken?: string | null) => void
  updateAccessToken: (accessToken: string, refreshToken?: string | null) => void
  logout: () => void
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      user: null,
      accessToken: null,
      refreshToken: null,
      isAuthenticated: false,

      setSession: (user, accessToken, refreshToken) =>
        set({
          user,
          accessToken,
          refreshToken: refreshToken ?? null,
          isAuthenticated: true,
        }),

      updateAccessToken: (accessToken, refreshToken) =>
        set((state) => ({
          accessToken,
          refreshToken: refreshToken ?? state.refreshToken,
          isAuthenticated: !!accessToken,
        })),

      logout: () =>
        set({
          user: null,
          accessToken: null,
          refreshToken: null,
          isAuthenticated: false,
        }),
    }),
    {
      name: 'gatestack-auth',
      partialize: (state) => ({
        user: state.user,
        accessToken: state.accessToken,
        refreshToken: state.refreshToken,
        isAuthenticated: state.isAuthenticated,
      }),
    },
  ),
)
