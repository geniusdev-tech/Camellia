import type { FileItem, ScanFileResponse } from '@/lib/types'

const STORAGE_KEY = 'camellia-scan-cache'

interface CachedScanEntry {
  file: {
    path: string
    size: number
    is_encrypted: boolean
  }
  report: ScanFileResponse
  saved_at: number
}

type CacheMap = Record<string, CachedScanEntry>

function readCache(): CacheMap {
  if (typeof window === 'undefined') return {}
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY)
    return raw ? JSON.parse(raw) as CacheMap : {}
  } catch {
    return {}
  }
}

function writeCache(cache: CacheMap): void {
  if (typeof window === 'undefined') return
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(cache))
  } catch {}
}

export function getCachedScan(file: FileItem): ScanFileResponse | null {
  const entry = readCache()[file.path]
  if (!entry) return null
  if (
    entry.file.path !== file.path ||
    entry.file.size !== file.size ||
    entry.file.is_encrypted !== file.is_encrypted
  ) {
    invalidateCachedScan(file.path)
    return null
  }
  return entry.report
}

export function setCachedScan(file: FileItem, report: ScanFileResponse): void {
  const cache = readCache()
  cache[file.path] = {
    file: {
      path: file.path,
      size: file.size,
      is_encrypted: file.is_encrypted,
    },
    report,
    saved_at: Date.now(),
  }
  writeCache(cache)
}

export function invalidateCachedScan(path: string): void {
  const cache = readCache()
  if (!(path in cache)) return
  delete cache[path]
  writeCache(cache)
}

export function moveCachedScan(oldPath: string, nextFile: FileItem): void {
  const cache = readCache()
  const previous = cache[oldPath]
  if (!previous) return
  delete cache[oldPath]
  cache[nextFile.path] = {
    ...previous,
    file: {
      path: nextFile.path,
      size: nextFile.size,
      is_encrypted: nextFile.is_encrypted,
    },
  }
  writeCache(cache)
}
