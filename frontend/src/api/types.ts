// API Response types
export interface ApiResponse {
    success: boolean
    msg?: string
    message?: string
    [key: string]: any
}

// User types
export interface User {
    email: string
    has_2fa: boolean
}

export interface LoginResponse extends ApiResponse {
    requires_2fa?: boolean
    requires_mfa?: boolean
    email?: string
    has_2fa?: boolean
    user_id?: number | string
}

export interface LoginMFARequest {
    code: string
    user_id: number | string
}

export interface RegisterRequest {
    email: string
    password: string
}

export interface LoginRequest {
    email: string
    password: string
}

export interface Verify2FARequest {
    code: string
}

export interface Setup2FAResponse extends ApiResponse {
    secret: string
    qr_code: string
}

// File & Vault types
export interface FileItem {
    name: string
    path: string
    is_dir: boolean
    is_encrypted: boolean
    size: number
    uuid?: string
}

export interface ListFilesRequest {
    path: string
    device_id?: string
}

export interface ListFilesResponse extends ApiResponse {
    items: FileItem[]
    current_path: string
    parent_path: string | null
}

// Process/Task types
export interface ProcessStatus {
    task_id: string
    progress: number
    status: string
    done: boolean
    logs: string[]
    eta?: number
}

export interface StartProcessRequest {
    targets: string[]
    encrypt: boolean
    recursive?: boolean
    device_id?: string
}

export interface BatchProcessRequest {
    targets: string[]
    encrypt: boolean
    recursive: boolean
    device_id: string
}

export interface BatchProcessResponse extends ApiResponse {
    task_id: string
}

// Device types
export interface Device {
    id: string
    name: string
    type: 'local' | 'usb' | 'mtp'
    path: string
}

export interface ListDevicesResponse extends ApiResponse {
    devices: Device[]
}

// File actions
export type FileAction = 'delete' | 'rename'

export interface FileActionRequest {
    action: FileAction
    path: string
    new_name?: string
}
