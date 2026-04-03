import { beforeEach, describe, expect, it } from 'vitest'
import { useAuthStore } from './auth'

describe('auth store', () => {
  beforeEach(() => {
    useAuthStore.getState().logout()
  })

  it('stores a full session including refresh token', () => {
    useAuthStore.getState().setSession(
      { user_id: 7, email: 'owner@example.com', has_2fa: true, role: 'owner' },
      'access-token',
      'refresh-token',
    )

    const state = useAuthStore.getState()
    expect(state.isAuthenticated).toBe(true)
    expect(state.accessToken).toBe('access-token')
    expect(state.refreshToken).toBe('refresh-token')
    expect(state.user?.role).toBe('owner')
  })

  it('updates access token without dropping existing refresh token', () => {
    useAuthStore.getState().setSession(
      { user_id: 9, email: 'user@example.com', has_2fa: false, role: 'user' },
      'old-access',
      'stable-refresh',
    )

    useAuthStore.getState().updateAccessToken('new-access')
    const state = useAuthStore.getState()

    expect(state.accessToken).toBe('new-access')
    expect(state.refreshToken).toBe('stable-refresh')
    expect(state.isAuthenticated).toBe(true)
  })

  it('clears the entire session on logout', () => {
    useAuthStore.getState().setSession(
      { user_id: 1, email: 'a@b.com', has_2fa: false, role: 'user' },
      'access',
      'refresh',
    )

    useAuthStore.getState().logout()
    const state = useAuthStore.getState()

    expect(state.user).toBeNull()
    expect(state.accessToken).toBeNull()
    expect(state.refreshToken).toBeNull()
    expect(state.isAuthenticated).toBe(false)
  })
})
