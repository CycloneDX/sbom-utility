// SPDX-License-Identifier: Apache-2.0
/**
 * mockBridge.ts — browser bridge backed by the local sbom-utility HTTP server.
 */

import type { SbomBridge, BomInfo, RunResult, ValidateParams, ListParams, DiffParams, PatchParams } from '../preload/index'

const API_BASE = (window as Window & { __SBOM_API_BASE__?: string }).__SBOM_API_BASE__ ?? 'http://127.0.0.1:8787/api'

const fileStore = new Map<string, string>()
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

function pickFile(accept = ''): Promise<File | null> {
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
  openFile: async () => {
    try {
      const file = await pickFile('.json,.xml')
      if (!file) return null
      const uploaded = await uploadFile(file)
      fileStore.set(uploaded.filePath, uploaded.content)
      return uploaded.filePath
    } catch (error: unknown) {
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
  getVersion: async () => '0.16.0-browser-dev',
  isDarkMode: async () => window.matchMedia('(prefers-color-scheme: dark)').matches,
}
