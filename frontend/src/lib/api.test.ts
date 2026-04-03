import { beforeEach, describe, expect, it, vi } from 'vitest'
import { authAPI } from './api'
import { useAuthStore } from '@/store/auth'

vi.mock('./tauri', () => ({
  getApiBase: vi.fn(async () => 'http://localhost:5000'),
}))

describe('authAPI refresh queue', () => {
  beforeEach(() => {
    useAuthStore.getState().logout()
    useAuthStore.getState().setSession(
      { user_id: 1, email: 'owner@example.com', has_2fa: false, role: 'owner' },
      'access-1',
      'refresh-1',
    )
  })

  it('reuses a single in-flight refresh request', async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({
      success: true,
      access_token: 'access-2',
      refresh_token: 'refresh-2',
    }), { status: 200, headers: { 'content-type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)

    await Promise.all([authAPI.refresh(), authAPI.refresh(), authAPI.refresh()])

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(useAuthStore.getState().accessToken).toBe('access-2')
    expect(useAuthStore.getState().refreshToken).toBe('refresh-2')
  })
})
