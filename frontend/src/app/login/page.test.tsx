import React from 'react'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import LoginPage from './page'
import { useAuthStore } from '@/store/auth'

const { replace, login, loginMFA, register } = vi.hoisted(() => ({
  replace: vi.fn(),
  login: vi.fn(),
  loginMFA: vi.fn(),
  register: vi.fn(),
}))

vi.mock('next/navigation', () => ({
  useRouter: () => ({ replace }),
}))

vi.mock('@/lib/api', () => ({
  authAPI: {
    login,
    loginMFA,
    register,
  },
}))

describe('LoginPage', () => {
  beforeEach(() => {
    replace.mockReset()
    login.mockReset()
    loginMFA.mockReset()
    register.mockReset()
    useAuthStore.getState().logout()
  })

  it('stores session and redirects on normal login', async () => {
    login.mockResolvedValue({
      success: true,
      access_token: 'access',
      refresh_token: 'refresh',
      email: 'owner@example.com',
      has_2fa: true,
      role: 'owner',
      user_id: 7,
    })

    render(React.createElement(LoginPage))

    fireEvent.change(screen.getAllByTestId('login-email')[0], { target: { value: 'owner@example.com' } })
    fireEvent.change(screen.getAllByTestId('login-password')[0], { target: { value: 'Owner-pass-123!' } })
    fireEvent.click(document.querySelector('button[type="submit"]') as HTMLButtonElement)

    await waitFor(() => expect(replace).toHaveBeenCalledWith('/dashboard'))
    expect(useAuthStore.getState().refreshToken).toBe('refresh')
    expect(useAuthStore.getState().user?.role).toBe('owner')
  })

  it('switches to MFA mode and verifies second factor', async () => {
    login.mockResolvedValue({
      success: false,
      requires_mfa: true,
      user_id: 9,
    })

    loginMFA.mockResolvedValue({
      success: true,
      access_token: 'access-mfa',
      refresh_token: 'refresh-mfa',
      email: 'user@example.com',
      role: 'user',
      user_id: 9,
    })

    render(React.createElement(LoginPage))

    fireEvent.change(screen.getAllByTestId('login-email')[0], { target: { value: 'user@example.com' } })
    fireEvent.change(screen.getAllByTestId('login-password')[0], { target: { value: 'User-pass-123!' } })
    fireEvent.click(document.querySelector('button[type="submit"]') as HTMLButtonElement)

    await screen.findByPlaceholderText('000 000')
    fireEvent.change(screen.getByPlaceholderText('000 000'), { target: { value: '123456' } })
    fireEvent.click(screen.getByRole('button', { name: /verificar/i }))

    await waitFor(() => expect(loginMFA).toHaveBeenCalled())
    expect(useAuthStore.getState().user?.user_id).toBe(9)
  })
})
