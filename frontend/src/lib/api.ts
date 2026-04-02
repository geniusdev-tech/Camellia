/**
 * Camellia Shield API Client
 * Works in both Next.js dev (proxied to :5000) and Tauri prod (direct to dynamic port).
 */

import type {
  ApiResponse, LoginRequest, LoginResponse, LoginMFARequest,
  RegisterRequest, Verify2FARequest, Setup2FAResponse,
  ListFilesRequest, ListFilesResponse, BatchProcessRequest,
  BatchProcessResponse, ProcessStatus, ListDevicesResponse,
  FileActionRequest, ProjectListResponse, ProjectUploadResponse,
} from './types'
import { getApiBase } from './tauri'

async function fetchAPI<T = ApiResponse>(
  endpoint: string,
  init?: RequestInit,
): Promise<T> {
  const base = await getApiBase()
  const token = typeof localStorage !== 'undefined'
    ? (JSON.parse(localStorage.getItem('camellia-auth') || '{}') as { state?: { accessToken?: string } })
        ?.state?.accessToken ?? ''
    : ''

  const isFormData = typeof FormData !== 'undefined' && init?.body instanceof FormData
  const headers: HeadersInit = {
    ...(isFormData ? {} : { 'Content-Type': 'application/json' }),
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(init?.headers as Record<string, string> ?? {}),
  }

  const res = await fetch(`${base}${endpoint}`, {
    ...init,
    headers,
    credentials: 'include',
  })

  if (res.status === 401) {
    // Clear auth & redirect — only in browser
    if (typeof window !== 'undefined') {
      localStorage.removeItem('camellia-auth')
      window.location.href = '/login'
    }
    throw new Error('Unauthorized')
  }

  return res.json() as Promise<T>
}

/* ── Auth ─────────────────────────────────────────── */
export const authAPI = {
  login:    (d: LoginRequest) =>
    fetchAPI<LoginResponse>('/api/auth/login', { method: 'POST', body: JSON.stringify(d) }),

  loginMFA: (d: LoginMFARequest) =>
    fetchAPI<LoginResponse>('/api/auth/login/mfa', { method: 'POST', body: JSON.stringify(d) }),

  register: (d: RegisterRequest) =>
    fetchAPI<ApiResponse>('/api/auth/register', { method: 'POST', body: JSON.stringify(d) }),

  logout:   () =>
    fetchAPI<ApiResponse>('/api/auth/logout', { method: 'POST' }),

  status:   () =>
    fetchAPI<LoginResponse>('/api/auth/status'),

  setup2FA: () =>
    fetchAPI<Setup2FAResponse>('/api/auth/mfa/setup', { method: 'POST' }),

  confirm2FA: (_secret: string, code: string) =>
    fetchAPI<ApiResponse>('/api/auth/mfa/verify', { method: 'POST', body: JSON.stringify({ code }) }),

  verify2FA: (d: Verify2FARequest) =>
    fetchAPI<ApiResponse>('/api/auth/mfa/verify', { method: 'POST', body: JSON.stringify(d) }),

  disable2FA: () =>
    fetchAPI<ApiResponse>('/api/auth/mfa/disable', { method: 'POST' }),
}

/* ── Vault ────────────────────────────────────────── */
export const vaultAPI = {
  listFiles: (d: ListFilesRequest) =>
    fetchAPI<ListFilesResponse>('/api/files/list', { method: 'POST', body: JSON.stringify(d) }),

  fileAction: (d: FileActionRequest) =>
    fetchAPI<ApiResponse>('/api/files/action', { method: 'POST', body: JSON.stringify(d) }),

  batchProcess: (d: BatchProcessRequest) =>
    fetchAPI<BatchProcessResponse>('/api/process/batch', { method: 'POST', body: JSON.stringify(d) }),

  getProcessStatus: (id: string) =>
    fetchAPI<ProcessStatus>(`/api/process/status/${id}`),

  cancelProcess: (id: string) =>
    fetchAPI<ApiResponse>('/api/process/cancel', { method: 'POST', body: JSON.stringify({ task_id: id }) }),

  scanFile: (path: string) =>
    fetchAPI('/api/security/scan', { method: 'POST', body: JSON.stringify({ path }) }),
}

/* ── Devices ──────────────────────────────────────── */
export const deviceAPI = {
  listDevices: () => fetchAPI<ListDevicesResponse>('/api/devices/list'),
}

/* ── Projects ─────────────────────────────────────── */
export const projectsAPI = {
  list: () => fetchAPI<ProjectListResponse>('/api/projects/list'),

  upload: (file: File) => {
    const form = new FormData()
    form.append('file', file)
    return fetchAPI<ProjectUploadResponse>('/api/projects/upload', {
      method: 'POST',
      body: form,
    })
  },
}
