// SPDX-License-Identifier: Apache-2.0
/**
 * Preload Script — src/preload/index.ts
 *
 * This is the ONLY bridge between the sandboxed renderer and the main process.
 * It uses contextBridge.exposeInMainWorld to create a typed, minimal API that
 * the renderer can call.  No Node.js modules are exposed directly.
 *
 * Security principles:
 *   - Only explicitly declared methods are exposed (allowlist, not denylist).
 *   - The renderer calls `window.sbomBridge.*`; it cannot reach ipcRenderer
 *     directly or call any arbitrary IPC channel.
 *   - All argument types are primitives or plain objects — no callback injection.
 */

import { contextBridge, ipcRenderer } from 'electron'

// ── Public API surface ────────────────────────────────────────────────────────

export interface BomInfo {
  filePath:    string
  specVersion: string
  format:      string
}

export interface RunResult {
  stdout: string
  stderr: string
  code:   number
}

export interface ValidateParams {
  filePath:    string
  variant?:    string
  forceSchema?: string
  maxErrors?:  number
  showValues?: boolean
}

export interface ListParams {
  filePath: string
  format?:  string
  where?:   string
  summary?: boolean
  resourceType?: string
}

export interface SbomBridge {
  // File system
  openFile():                                   Promise<string | null>
  readFile(filePath: string):                   Promise<string>
  // BOM metadata
  getBomInfo(filePath: string):                 Promise<BomInfo>
  // Commands
  validate(params: ValidateParams):             Promise<RunResult>
  listLicenses(params: ListParams):             Promise<RunResult>
  listComponents(params: ListParams):           Promise<RunResult>
  listResources(params: ListParams):            Promise<RunResult>
  listVulnerabilities(params: ListParams):      Promise<RunResult>
  // App
  getVersion():                                 Promise<string>
  isDarkMode():                                 Promise<boolean>
}

// ── Implementation ────────────────────────────────────────────────────────────

const bridge: SbomBridge = {
  openFile:            ()       => ipcRenderer.invoke('dialog:openFile'),
  readFile:            (p)      => ipcRenderer.invoke('fs:readFile',             p),
  getBomInfo:          (p)      => ipcRenderer.invoke('bom:info',                p),
  validate:            (params) => ipcRenderer.invoke('bom:validate',            params),
  listLicenses:        (params) => ipcRenderer.invoke('bom:listLicenses',        params),
  listComponents:      (params) => ipcRenderer.invoke('bom:listComponents',      params),
  listResources:       (params) => ipcRenderer.invoke('bom:listResources',       params),
  listVulnerabilities: (params) => ipcRenderer.invoke('bom:listVulnerabilities', params),
  getVersion:          ()       => ipcRenderer.invoke('app:version'),
  isDarkMode:          ()       => ipcRenderer.invoke('app:isDarkMode'),
}

contextBridge.exposeInMainWorld('sbomBridge', bridge)
