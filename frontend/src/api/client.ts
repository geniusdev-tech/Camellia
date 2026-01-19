import type {
    ApiResponse,
    LoginRequest,
    LoginResponse,
    LoginMFARequest,
    RegisterRequest,
    Verify2FARequest,
    Setup2FAResponse,
    ListFilesRequest,
    ListFilesResponse,
    BatchProcessRequest,
    BatchProcessResponse,
    ProcessStatus,
    ListDevicesResponse,
    FileActionRequest
} from './types'

const API_BASE = import.meta.env.VITE_API_BASE_URL || ''

import { useAuthStore } from '../store/authStore'

// Generic fetch wrapper with error handling
async function fetchAPI<T = any>(
    endpoint: string,
    options?: RequestInit
): Promise<T> {
    try {
        const { accessToken } = useAuthStore.getState()

        const headers: Record<string, string> = {
            'Content-Type': 'application/json',
            ...(options?.headers as Record<string, string>),
        }

        if (accessToken) {
            headers['Authorization'] = `Bearer ${accessToken}`
        }

        const response = await fetch(`${API_BASE}${endpoint}`, {
            ...options,
            headers,
            credentials: 'include', // Important for session cookies
        })

        if (!response.ok && response.status === 401) {
            // Unauthorized - redirect to login
            window.location.href = '/login'
            throw new Error('Unauthorized')
        }

        const data = await response.json()
        return data
    } catch (error) {
        console.error(`API Error [${endpoint}]:`, error)
        throw error
    }
}

// Authentication API
export const authAPI = {
    async login(credentials: LoginRequest): Promise<LoginResponse> {
        return fetchAPI('/api/auth/login', {
            method: 'POST',
            body: JSON.stringify(credentials),
        })
    },

    async loginMFA(data: LoginMFARequest): Promise<LoginResponse> {
        return fetchAPI('/api/auth/login/mfa', {
            method: 'POST',
            body: JSON.stringify(data),
        })
    },

    async register(data: RegisterRequest): Promise<ApiResponse> {
        return fetchAPI('/api/auth/register', {
            method: 'POST',
            body: JSON.stringify(data),
        })
    },

    async logout(): Promise<ApiResponse> {
        return fetchAPI('/api/auth/logout', {
            method: 'POST',
        })
    },

    async getStatus(): Promise<LoginResponse> {
        return fetchAPI('/api/auth/status')
    },

    async verify2FA(data: Verify2FARequest): Promise<ApiResponse> {
        return fetchAPI('/api/auth/mfa/verify', {
            method: 'POST',
            body: JSON.stringify(data),
        })
    },

    async setup2FA(): Promise<Setup2FAResponse> {
        return fetchAPI('/api/auth/mfa/setup', {
            method: 'POST',
        })
    },

    async confirm2FA(_secret: string, code: string): Promise<ApiResponse> {
        return fetchAPI('/api/auth/mfa/verify', {
            method: 'POST',
            body: JSON.stringify({ code }), // Backend ignores secret, uses session
        })
    },

    async disable2FA(): Promise<ApiResponse> {
        return fetchAPI('/api/auth/mfa/disable', {
            method: 'POST',
        })
    },
}

// Vault/File API
export const vaultAPI = {
    async listFiles(data: ListFilesRequest): Promise<ListFilesResponse> {
        return fetchAPI('/api/files/list', {
            method: 'POST',
            body: JSON.stringify(data),
        })
    },

    async fileAction(data: FileActionRequest): Promise<ApiResponse> {
        return fetchAPI('/api/files/action', {
            method: 'POST',
            body: JSON.stringify(data),
        })
    },

    async batchProcess(data: BatchProcessRequest): Promise<BatchProcessResponse> {
        return fetchAPI('/api/process/batch', {
            method: 'POST',
            body: JSON.stringify(data),
        })
    },

    async getProcessStatus(taskId: string): Promise<ProcessStatus> {
        return fetchAPI(`/api/process/status/${taskId}`)
    },

    async cancelProcess(taskId: string): Promise<ApiResponse> {
        return fetchAPI('/api/process/cancel', {
            method: 'POST',
            body: JSON.stringify({ task_id: taskId }),
        })
    },

    async scanFile(path: string): Promise<any> {
        return fetchAPI('/api/security/scan', {
            method: 'POST',
            body: JSON.stringify({ path }),
        })
    },
}

// Device API
export const deviceAPI = {
    async listDevices(): Promise<ListDevicesResponse> {
        return fetchAPI('/api/devices/list')
    },
}
