/**
 * Tauri integration helpers.
 * Gracefully falls back to empty string (Next.js proxy) when running in the browser.
 */

let _cachedBase: string | null = null

export async function getApiBase(): Promise<string> {
  if (_cachedBase !== null) return _cachedBase

  // SSR: always use empty base (Next.js handles rewrites)
  if (typeof window === 'undefined') {
    _cachedBase = ''
    return ''
  }

  // Check if we're inside a Tauri webview
  const w = window as unknown as { __TAURI__?: unknown }
  if (w.__TAURI__) {
    try {
      const { invoke } = await import('@tauri-apps/api/core')
      const port = await invoke<number>('get_backend_port')
      _cachedBase = `http://127.0.0.1:${port}`
      return _cachedBase
    } catch (e) {
      console.error('[Tauri] Failed to get backend port, using default 5000', e)
      _cachedBase = 'http://127.0.0.1:5000'
      return _cachedBase
    }
  }

  // Plain browser dev / prod
  _cachedBase = ''
  return ''
}

export function isTauri(): boolean {
  if (typeof window === 'undefined') return false
  return !!(window as unknown as { __TAURI__?: unknown }).__TAURI__
}

/** Show Tauri native notification (no-op in browser). */
export async function notify(title: string, body: string) {
  if (!isTauri()) return
  try {
    const { sendNotification } = await import('@tauri-apps/plugin-notification')
    await sendNotification({ title, body })
  } catch {}
}
