import type {
  ApiResponse,
  AsyncJobListResponse,
  AsyncJobResponse,
  DownloadResponse,
  LoginMFARequest,
  LoginRequest,
  LoginResponse,
  MetricsResponse,
  PackageVersionMatrixResponse,
  ProjectDetailResponse,
  ProjectHistoryResponse,
  ProjectListResponse,
  ProjectUploadResponse,
  PublicLatestResponse,
  PublicPackageDetailResponse,
  PublicPackageListResponse,
  PublicVersionResponse,
  RegisterRequest,
  Setup2FAResponse,
  TeamCreateResponse,
  TeamInviteResponse,
  TeamListResponse,
  Verify2FARequest,
} from './types'
import { getApiBase } from './tauri'
import { useAuthStore } from '@/store/auth'

const REQUEST_TIMEOUT_MS = 10_000
const RETRY_DELAY_MS = 350
let refreshInFlight: Promise<boolean> | null = null

type SessionSnapshot = {
  accessToken: string | null
  refreshToken: string | null
  isAuthenticated: boolean
}

let cachedSession: SessionSnapshot = {
  accessToken: useAuthStore.getState().accessToken,
  refreshToken: useAuthStore.getState().refreshToken,
  isAuthenticated: useAuthStore.getState().isAuthenticated,
}

useAuthStore.subscribe((state) => {
  cachedSession = {
    accessToken: state.accessToken,
    refreshToken: state.refreshToken,
    isAuthenticated: state.isAuthenticated,
  }
})

class ApiError extends Error {
  status: number
  body: unknown

  constructor(message: string, status: number, body: unknown) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.body = body
  }
}

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function isRetryableMethod(method?: string) {
  const normalized = (method || 'GET').toUpperCase()
  return normalized === 'GET' || normalized === 'HEAD'
}

function extractMessage(body: unknown, fallback: string) {
  if (body && typeof body === 'object') {
    const candidate = body as { msg?: unknown; message?: unknown; error?: unknown }
    if (typeof candidate.msg === 'string' && candidate.msg.trim()) return candidate.msg
    if (typeof candidate.message === 'string' && candidate.message.trim()) return candidate.message
    if (typeof candidate.error === 'string' && candidate.error.trim()) return candidate.error
  }

  return fallback
}

async function parseResponseBody(res: Response): Promise<unknown> {
  const raw = (await res.text()).trim()
  if (!raw) return null

  const contentType = res.headers.get('content-type') || ''
  if (contentType.includes('application/json')) {
    try {
      return JSON.parse(raw)
    } catch {
      return { message: 'Invalid JSON response', raw }
    }
  }

  try {
    return JSON.parse(raw)
  } catch {
    return { message: raw }
  }
}

async function runRequest(input: RequestInfo | URL, init: RequestInit, timeoutMs: number): Promise<Response> {
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs)

  try {
    return await fetch(input, { ...init, signal: controller.signal })
  } finally {
    clearTimeout(timeoutId)
  }
}

async function performRefresh(base: string): Promise<boolean> {
  const store = useAuthStore.getState()
  if (!store.refreshToken) return false

  try {
    const response = await runRequest(`${base}/api/auth/refresh`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: store.refreshToken }),
    }, REQUEST_TIMEOUT_MS)

    const body = await parseResponseBody(response) as LoginResponse | null
    if (!response.ok || !body?.access_token) {
      store.logout()
      return false
    }

    store.updateAccessToken(body.access_token, body.refresh_token ?? null)
    return true
  } catch {
    store.logout()
    return false
  }
}

async function ensureRefreshed(base: string) {
  if (!refreshInFlight) {
    refreshInFlight = performRefresh(base).finally(() => {
      refreshInFlight = null
    })
  }
  return refreshInFlight
}

async function fetchAPI<T = ApiResponse>(
  endpoint: string,
  init?: RequestInit,
  options?: { skipAuthRefresh?: boolean; allowRetry?: boolean; timeoutMs?: number },
): Promise<T> {
  const base = await getApiBase()
  const method = (init?.method || 'GET').toUpperCase()
  const store = useAuthStore.getState()

  const allowRetry = options?.allowRetry ?? isRetryableMethod(method)
  const timeoutMs = options?.timeoutMs ?? REQUEST_TIMEOUT_MS
  const isFormData = typeof FormData !== 'undefined' && init?.body instanceof FormData

  const buildHeaders = (): HeadersInit => {
    const session = cachedSession
    return {
      ...(isFormData ? {} : { 'Content-Type': 'application/json' }),
      ...(session.accessToken ? { Authorization: `Bearer ${session.accessToken}` } : {}),
      ...((init?.headers as Record<string, string> | undefined) ?? {}),
    }
  }

  const doRequest = async (): Promise<Response> => {
    let response: Response | undefined
    let lastError: unknown
    const maxAttempts = allowRetry ? 2 : 1

    for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
      try {
        response = await runRequest(
          `${base}${endpoint}`,
          {
            ...init,
            headers: buildHeaders(),
            credentials: 'include',
          },
          timeoutMs,
        )
        if (response.ok || !allowRetry || attempt === maxAttempts - 1 || response.status < 500) {
          return response
        }
      } catch (error) {
        lastError = error
        if (!allowRetry || attempt === maxAttempts - 1 || !isRetryableMethod(method)) {
          const isAbortError =
            typeof DOMException !== 'undefined' &&
            error instanceof DOMException &&
            error.name === 'AbortError'
          if (isAbortError) {
            throw new Error('Tempo limite excedido ao comunicar com o servidor.')
          }
          throw error instanceof Error ? error : new Error('Falha de rede.')
        }
      }

      if (attempt < maxAttempts - 1) {
        await sleep(RETRY_DELAY_MS * (attempt + 1))
      }
    }

    if (response) {
      return response
    }
    throw lastError instanceof Error ? lastError : new Error('Falha de rede.')
  }

  let res = await doRequest()
  let body = await parseResponseBody(res)

  if (
    res.status === 401 &&
    !options?.skipAuthRefresh &&
    store.refreshToken &&
    !endpoint.startsWith('/api/auth/')
  ) {
    const refreshed = await ensureRefreshed(base)
    if (refreshed) {
      res = await doRequest()
      body = await parseResponseBody(res)
    }
  }

  if (res.status === 401) {
    if (typeof window !== 'undefined') {
      useAuthStore.getState().logout()
      window.location.href = '/login'
    }
    throw new Error('Unauthorized')
  }

  if (!res.ok) {
    throw new ApiError(
      extractMessage(body, `Request failed with status ${res.status}`),
      res.status,
      body,
    )
  }

  return (body ?? {}) as T
}

type ProjectListParams = {
  search?: string
  visibility?: string
  status?: string
  package_name?: string
  package_version?: string
  checksum_sha256?: string
  scope?: string
  user_id?: number | string
  page?: number
  page_size?: number
  sort_by?: string
  sort_dir?: string
}

function queryString(params?: Record<string, string | number | boolean | undefined | null>) {
  const qs = new URLSearchParams()
  Object.entries(params || {}).forEach(([key, value]) => {
    if (value === undefined || value === null || value === '') return
    qs.set(key, String(value))
  })
  const encoded = qs.toString()
  return encoded ? `?${encoded}` : ''
}

export const authAPI = {
  login: (d: LoginRequest) =>
    fetchAPI<LoginResponse>('/api/auth/login', { method: 'POST', body: JSON.stringify(d) }, { skipAuthRefresh: true }),

  loginMFA: (d: LoginMFARequest) =>
    fetchAPI<LoginResponse>('/api/auth/login/mfa', { method: 'POST', body: JSON.stringify(d) }, { skipAuthRefresh: true }),

  register: (d: RegisterRequest) =>
    fetchAPI<ApiResponse>('/api/auth/register', { method: 'POST', body: JSON.stringify(d) }, { skipAuthRefresh: true }),

  refresh: async () => {
    const base = await getApiBase()
    return ensureRefreshed(base)
  },

  logout: () =>
    fetchAPI<ApiResponse>('/api/auth/logout', { method: 'POST' }),

  logoutAll: () =>
    fetchAPI<ApiResponse>('/api/auth/logout-all', { method: 'POST' }),

  status: () =>
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

export const projectsAPI = {
  list: (params?: ProjectListParams) =>
    fetchAPI<ProjectListResponse>(`/api/projects/list${queryString(params)}`),

  get: (projectId: string) =>
    fetchAPI<ProjectDetailResponse>(`/api/projects/${projectId}`),

  history: (projectId: string) =>
    fetchAPI<ProjectHistoryResponse>(`/api/projects/${projectId}/history`),

  versionMatrix: (packageName: string) =>
    fetchAPI<PackageVersionMatrixResponse>(`/api/projects/package/${encodeURIComponent(packageName)}/versions`),

  upload: (payload: {
    file: File
    packageName?: string
    packageVersion?: string
    description?: string
    changelog?: string
    visibility?: string
    metadata?: Record<string, unknown>
    sharedWith?: number[]
  }) => {
    const form = new FormData()
    form.append('file', payload.file)
    if (payload.packageName) form.append('package_name', payload.packageName)
    if (payload.packageVersion) form.append('package_version', payload.packageVersion)
    if (payload.description) form.append('description', payload.description)
    if (payload.changelog) form.append('changelog', payload.changelog)
    if (payload.visibility) form.append('visibility', payload.visibility)
    if (payload.metadata) form.append('metadata', JSON.stringify(payload.metadata))
    if (payload.sharedWith?.length) form.append('shared_with', payload.sharedWith.join(','))

    return fetchAPI<ProjectUploadResponse>('/api/projects/upload', {
      method: 'POST',
      body: form,
    })
  },

  update: (
    projectId: string,
    payload: Record<string, unknown>,
  ) => fetchAPI<ProjectDetailResponse>(`/api/projects/${projectId}`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
  }),

  remove: (projectId: string) =>
    fetchAPI<ApiResponse>(`/api/projects/${projectId}`, { method: 'DELETE' }),

  download: (projectId: string, expiresIn = 900) =>
    fetchAPI<DownloadResponse>(`/api/projects/${projectId}/download${queryString({ expires_in: expiresIn })}`),
}

export const accessAPI = {
  listTeams: () =>
    fetchAPI<TeamListResponse>('/api/access/teams'),

  createTeam: (name: string) =>
    fetchAPI<TeamCreateResponse>('/api/access/teams', {
      method: 'POST',
      body: JSON.stringify({ name }),
    }),

  createInvite: (teamId: string, email: string, role = 'member', expiresAt?: string) =>
    fetchAPI<TeamInviteResponse>(`/api/access/teams/${teamId}/invites`, {
      method: 'POST',
      body: JSON.stringify({ email, role, expires_at: expiresAt }),
    }),

  acceptInvite: (token: string) =>
    fetchAPI<TeamCreateResponse>(`/api/access/invites/${token}/accept`, { method: 'POST' }),

  addProjectTeamGrant: (projectId: string, teamId: string, grantRole = 'viewer', expiresAt?: string) =>
    fetchAPI<ApiResponse>(`/api/access/projects/${projectId}/team-grants`, {
      method: 'POST',
      body: JSON.stringify({ team_id: teamId, grant_role: grantRole, expires_at: expiresAt }),
    }),
}

export const opsAPI = {
  metrics: () =>
    fetchAPI<MetricsResponse>('/api/ops/metrics'),

  listJobs: (projectId?: string) =>
    fetchAPI<AsyncJobListResponse>(`/api/ops/jobs${queryString({ project_id: projectId })}`),

  getJob: (jobId: string) =>
    fetchAPI<AsyncJobResponse>(`/api/ops/jobs/${jobId}`),

  enqueueProjectScan: (projectId: string) =>
    fetchAPI<ApiResponse>(`/api/ops/projects/${projectId}/scan`, { method: 'POST' }),

  enqueueProjectPublish: (projectId: string) =>
    fetchAPI<ApiResponse>(`/api/ops/projects/${projectId}/publish`, { method: 'POST' }),
}

export const publicPackagesAPI = {
  list: (params?: { search?: string; latest?: number; page?: number; page_size?: number }) =>
    fetchAPI<PublicPackageListResponse>(`/api/public/packages${queryString(params)}`, undefined, { skipAuthRefresh: true }),

  detail: (packageName: string) =>
    fetchAPI<PublicPackageDetailResponse>(`/api/public/packages/${encodeURIComponent(packageName)}`, undefined, { skipAuthRefresh: true }),

  latest: (packageName: string) =>
    fetchAPI<PublicLatestResponse>(`/api/public/packages/${encodeURIComponent(packageName)}/latest`, undefined, { skipAuthRefresh: true }),

  version: (packageName: string, version: string) =>
    fetchAPI<PublicVersionResponse>(`/api/public/packages/${encodeURIComponent(packageName)}/versions/${encodeURIComponent(version)}`, undefined, { skipAuthRefresh: true }),

  download: (packageName: string, version: string, expiresIn = 900) =>
    fetchAPI<DownloadResponse>(
      `/api/public/packages/${encodeURIComponent(packageName)}/versions/${encodeURIComponent(version)}/download${queryString({ expires_in: expiresIn })}`,
      undefined,
      { skipAuthRefresh: true },
    ),
}

export { ApiError, fetchAPI }
