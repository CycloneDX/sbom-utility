// SPDX-License-Identifier: Apache-2.0
/**
 * mockBridge.ts — browser bridge backed by the local sbom-utility HTTP server.
 */

import type { SbomBridge, OpenFileResult, BomInfo, RunResult, ValidateParams, ListParams, DiffParams, PatchParams, PreferencesResult, UserPreferences } from '../preload/index'

const API_BASE = (window as Window & { __SBOM_API_BASE__?: string }).__SBOM_API_BASE__ ?? 'http://127.0.0.1:8787/api'

const fileStore       = new Map<string, string>()
const saveHandleStore = new Map<string, FileSystemFileHandle>()

async function postJSON<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: response.statusText })) as { error?: string }
    throw new Error(error.error ?? response.statusText)
  }

  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

// ── Directory handle persistence (IndexedDB) ─────────────────────────────────
// FileSystemHandle objects cannot be serialised to localStorage, but IndexedDB
// can store them directly.  We persist the last-used directory handle so the
// "Load BOM" dialog reopens in the same folder across page refreshes.

const IDB_DB   = 'sbom-gui'
const IDB_STORE = 'handles'
const IDB_KEY   = 'lastBomDirectory'

function openHandleDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(IDB_DB, 1)
    req.onupgradeneeded = () => req.result.createObjectStore(IDB_STORE)
    req.onsuccess = () => resolve(req.result)
    req.onerror   = () => reject(req.error)
  })
}

async function saveDirectoryHandle(handle: FileSystemHandle): Promise<void> {
  try {
    const db = await openHandleDB()
    await new Promise<void>((resolve, reject) => {
      const tx  = db.transaction(IDB_STORE, 'readwrite')
      const req = tx.objectStore(IDB_STORE).put(handle, IDB_KEY)
      req.onsuccess = () => resolve()
      req.onerror   = () => reject(req.error)
    })
  } catch { /* non-fatal */ }
}

async function loadDirectoryHandle(): Promise<FileSystemHandle | null> {
  try {
    const db = await openHandleDB()
    const handle = await new Promise<FileSystemHandle | undefined>((resolve, reject) => {
      const tx  = db.transaction(IDB_STORE, 'readonly')
      const req = tx.objectStore(IDB_STORE).get(IDB_KEY)
      req.onsuccess = () => resolve(req.result as FileSystemHandle | undefined)
      req.onerror   = () => reject(req.error)
    })
    return handle ?? null
  } catch {
    return null
  }
}

// In-memory cache; populated lazily on first openFile call
let directoryHandleCache: FileSystemHandle | null = null

async function pickFile(accept = '', _defaultDirectory?: string): Promise<File | null> {
  // Use File System Access API when available (Chrome, Edge, Opera)
  const win = window as Window & {
    showOpenFilePicker?: (options?: {
      multiple?: boolean
      startIn?: string | FileSystemHandle
      types?: Array<{ description: string; accept: Record<string, string[]> }>
    }) => Promise<FileSystemFileHandle[]>
  }

  if (typeof win.showOpenFilePicker === 'function') {
    // Populate cache from IndexedDB on first call this session
    if (!directoryHandleCache) {
      directoryHandleCache = await loadDirectoryHandle()
    }

    const startIn: string | FileSystemHandle = directoryHandleCache ?? 'documents'

    try {
      const [handle] = await win.showOpenFilePicker({
        multiple: false,
        startIn,
        types: [
          {
            description: 'BOM Files',
            accept: {
              'application/json': ['.json'],
              'application/xml': ['.xml'],
            },
          },
        ],
      })
      if (handle) {
        // Cache and persist the handle so next open starts in the same directory.
        directoryHandleCache = handle
        saveDirectoryHandle(handle) // fire-and-forget
        return await handle.getFile()
      }
    } catch (err: unknown) {
      if (err instanceof DOMException && err.name === 'AbortError') {
        return null
      }
      // Fall through to input element fallback
    }
  }

  return new Promise(resolve => {
    const input = document.createElement('input')
    input.type = 'file'
    input.accept = accept
    input.style.display = 'none'
    document.body.appendChild(input)

    let settled = false
    const finish = (file: File | null) => {
      if (settled) return
      settled = true
      if (document.body.contains(input)) {
        document.body.removeChild(input)
      }
      resolve(file)
    }

    input.addEventListener('change', () => {
      finish(input.files?.[0] ?? null)
    }, { once: true })

    window.addEventListener('focus', function onFocus() {
      window.removeEventListener('focus', onFocus)
      setTimeout(() => {
        if (!settled) {
          finish(null)
        }
      }, 300)
    }, { once: true })

    input.click()
  })
}

async function uploadFile(file: File): Promise<{ filePath: string; content: string }> {
  const form = new FormData()
  form.append('file', file)
  const response = await fetch(`${API_BASE}/open`, {
    method: 'POST',
    body: form,
  })

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: response.statusText })) as { error?: string }
    throw new Error(error.error ?? response.statusText)
  }

  return response.json() as Promise<{ filePath: string; content: string }>
}

export const mockBridge: SbomBridge = {
  pickDirectory: async (): Promise<string | null> => {
    const win = window as Window & {
      showDirectoryPicker?: () => Promise<FileSystemDirectoryHandle>
    }
    if (typeof win.showDirectoryPicker === 'function') {
      try {
        const handle = await win.showDirectoryPicker()
        if (handle) {
          directoryHandleCache = handle
          saveDirectoryHandle(handle) // fire-and-forget
          return handle.name
        }
      } catch (err: unknown) {
        if (err instanceof DOMException && err.name === 'AbortError') {
          return null
        }
      }
    }
    return null
  },

  openFile: async (defaultDirectory?: string): Promise<OpenFileResult | null> => {
    try {
      const file = await pickFile('.json,.xml', defaultDirectory)
      if (!file) return null
      const uploaded = await uploadFile(file)
      fileStore.set(uploaded.filePath, uploaded.content)
      // path  = server temp path (used for all backend ops)
      // displayName = original filename chosen by user (browser can't give more)
      return { path: uploaded.filePath, displayName: file.name }
    } catch (error: unknown) {
      if (error instanceof DOMException && error.name === 'AbortError') {
        return null
      }
      window.alert(`Failed to load file: ${error instanceof Error ? error.message : String(error)}`)
      throw error
    }
  },

  readFile: async (filePath: string) => {
    const cached = fileStore.get(filePath)
    if (cached !== undefined) return cached
    const response = await postJSON<{ content: string }>('/read', { filePath })
    fileStore.set(filePath, response.content)
    return response.content
  },

  saveFileDialog: async (defaultPath: string) => {
    if (typeof (window as Window & { showSaveFilePicker?: unknown }).showSaveFilePicker === 'function') {
      const suggestedName = defaultPath.split('/').pop() ?? 'sbom-edited.json'
      try {
        const handle = await (window as unknown as Window & {
          showSaveFilePicker(opts: {
            suggestedName: string
            types: { description: string; accept: Record<string, string[]> }[]
          }): Promise<FileSystemFileHandle>
        }).showSaveFilePicker({
          suggestedName,
          types: [
            { description: 'JSON files', accept: { 'application/json': ['.json'] } },
            { description: 'All files', accept: { '*/*': [] } },
          ],
        })
        const fakePath = `/browser-local/${handle.name}`
        saveHandleStore.set(fakePath, handle)
        return fakePath
      } catch {
        return null
      }
    }

    const suggestion = defaultPath.split('/').pop() ?? 'sbom-edited.json'
    const name = window.prompt('Save as filename:', suggestion)
    if (!name) return null
    return `/browser-local/${name}`
  },

  writeFile: async (filePath: string, content: string) => {
    const handle = saveHandleStore.get(filePath)
    if (handle) {
      const writable = await handle.createWritable()
      await writable.write(content)
      await writable.close()
      saveHandleStore.delete(filePath)
    }
    await postJSON<void>('/write', { filePath, content })
    fileStore.set(filePath, content)
  },

  getBomInfo: async (filePath: string): Promise<BomInfo> => postJSON('/bom-info', { filePath }),
  validate: async (params: ValidateParams): Promise<RunResult> => postJSON('/validate', params),
  listLicenses: async (params: ListParams): Promise<RunResult> => postJSON('/license/list', params),
  listComponents: async (params: ListParams): Promise<RunResult> => postJSON('/component/list', params),
  listResources: async (params: ListParams): Promise<RunResult> => postJSON('/resource/list', params),
  listVulnerabilities: async (params: ListParams): Promise<RunResult> => postJSON('/vulnerability/list', params),
  diffBoms: async (params: DiffParams): Promise<RunResult> => postJSON('/diff', params),
  applyPatch: async (params: PatchParams): Promise<RunResult> => postJSON('/patch', params),
  getPreferences: async (): Promise<PreferencesResult> => {
    try {
      const response = await fetch(`${API_BASE}/preferences`)
      if (response.ok) {
        return (await response.json()) as PreferencesResult
      }
    } catch {
      /* fallback below */
    }
    return {
      path: './preferences.json',
      exists: false,
      preferences: {
        editorFontFamily: 'ui-monospace, "Cascadia Code", "Fira Code", Consolas, "Courier New", monospace',
        editorFontSize: 13,
        autoValidateOnLoad: true,
      },
    }
  },
  savePreferences: async (prefs: UserPreferences): Promise<PreferencesResult> => {
    return postJSON<PreferencesResult>('/preferences', prefs)
  },
  getVersion: async () => '0.16.0-browser-dev',
  isDarkMode: async () => window.matchMedia('(prefers-color-scheme: dark)').matches,
}
