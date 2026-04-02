/* ── API response primitives ─────────────────────── */
export interface ApiResponse {
  success: boolean
  msg?: string
  message?: string
  [key: string]: unknown
}

/* ── Auth ─────────────────────────────────────────── */
export interface LoginRequest      { email: string; password: string }
export interface RegisterRequest   { email: string; password: string }
export interface LoginMFARequest   { code: string; user_id: number | string }
export interface Verify2FARequest  { code: string }

export interface LoginResponse extends ApiResponse {
  access_token?: string
  refresh_token?: string
  email?: string
  has_2fa?: boolean
  role?: string
  vault_unlocked?: boolean
  requires_mfa?: boolean
  requires_2fa?: boolean
  user_id?: number | string
}

export interface Setup2FAResponse extends ApiResponse {
  secret: string
  qr_code: string
}

export interface User {
  email: string
  has_2fa: boolean
}

/* ── Vault / Files ────────────────────────────────── */
export interface FileItem {
  name: string
  path: string
  is_dir: boolean
  is_encrypted: boolean
  size: number
  uuid?: string
  method?: string
}

export interface ListFilesRequest  { path: string; device_id?: string }

export interface ListFilesResponse extends ApiResponse {
  items: FileItem[]
  current_path: string
  parent_path: string | null
}

export interface FileActionRequest {
  action: 'delete' | 'rename'
  path: string
  new_name?: string
}

/* ── Process / Tasks ──────────────────────────────── */
export interface BatchProcessRequest {
  targets: string[]
  encrypt: boolean
  recursive: boolean
  device_id: string
}

export interface BatchProcessResponse extends ApiResponse {
  task_id: string
}

export interface ProcessStatus {
  task_id?: string
  progress: number
  status: string
  done: boolean
  logs: string[]
}

export interface ScanRiskAnalysis {
  level: 'LOW' | 'HIGH' | 'CRITICAL'
  entropy: number
  notes: string
}

export interface ScanHashes {
  sha256: string
  blake2b: string
}

export interface ScanFileResponse extends ApiResponse {
  path: string
  size: number
  hashes: ScanHashes
  risk_analysis: ScanRiskAnalysis
}

/* ── Devices ──────────────────────────────────────── */
export interface Device {
  id: string
  name: string
  type: 'local' | 'usb' | 'mtp'
  path: string
}

export interface ListDevicesResponse extends ApiResponse {
  devices: Device[]
}
