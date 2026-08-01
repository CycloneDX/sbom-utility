// SPDX-License-Identifier: Apache-2.0
/**
 * Electron Main Process — src/main/index.ts
 *
 * Security posture (Electron hardening guide, 2024):
 *   ✅  contextIsolation: true   — renderer cannot access Node APIs directly
 *   ✅  nodeIntegration: false   — no Node in renderer
 *   ✅  sandbox: true            — renderer is OS-sandboxed (Chromium sandbox)
 *   ✅  webSecurity: true        — same-origin enforced (default; explicit here)
 *   ✅  allowRunningInsecureContent: false
 *   ✅  experimentalFeatures: false
 *   ✅  CSP via session.webRequest header (overrides any meta-tag CSP)
 *   ✅  Navigation guard — disallows opening any URL except app origin
 *   ✅  New-window guard — blocks window.open() and <a target="_blank">
 *   ✅  shell.openExternal allowlist — only https: links are opened in browser
 *   ✅  IPC input validation in all handlers (see ipc-handlers.ts)
 *   ✅  sbom-utility binary path resolved from app.getPath('exe') / resources,
 *       never from user-supplied input
 */

import {
  app,
  BrowserWindow,
  ipcMain,
  dialog,
  shell,
  session,
  nativeTheme,
  Menu,
} from 'electron'
import * as path from 'path'
import { registerIpcHandlers } from './ipc-handlers'

// ── Dev / prod path resolution ───────────────────────────────────────────────

const isDev = !app.isPackaged

/**
 * Resolve the path to the bundled sbom-utility binary.
 *
 * In dev mode (unpackaged):  look for the binary next to the repo root.
 * In production (packaged):  electron-builder copies it to process.resourcesPath.
 */
function resolveBinaryPath(): string {
  const binaryName = process.platform === 'win32' ? 'sbom-utility.exe' : 'sbom-utility'
  if (isDev) {
    // Repo root is two levels up from gui-ts/src/main/
    return path.resolve(__dirname, '..', '..', '..', '..', binaryName)
  }
  return path.join(process.resourcesPath, binaryName)
}

/**
 * Resolve the path to the bundled config.json (schema config).
 */
function resolveConfigPath(): string {
  if (isDev) {
    return path.resolve(__dirname, '..', '..', '..', '..', 'resources', 'config', 'config.json')
  }
  return path.join(process.resourcesPath, 'config.json')
}

/**
 * Resolve the path to the bundled license.json (license policy).
 */
function resolveLicensePolicyPath(): string {
  if (isDev) {
    return path.resolve(__dirname, '..', '..', '..', '..', 'resources', 'config', 'license.json')
  }
  return path.join(process.resourcesPath, 'license.json')
}

// ── App version ──────────────────────────────────────────────────────────────

const APP_VERSION = app.getVersion()

// ── Window creation ──────────────────────────────────────────────────────────

let mainWindow: BrowserWindow | null = null

function createWindow(): void {
  mainWindow = new BrowserWindow({
    width:  1200,
    height: 760,
    minWidth:  900,
    minHeight: 600,
    title: `SBOM Utility  v${APP_VERSION}`,
    // Use native title bar on all platforms for the best OS integration.
    // macOS: shows the traffic lights + app name in the menu bar.
    titleBarStyle: 'default',
    backgroundColor: '#F5F5F5', // matches --color-bg in tokens.css
    show: false, // shown after 'ready-to-show' to avoid white flash
    webPreferences: {
      // ── Core security settings ──────────────────────────────────
      contextIsolation:             true,   // MUST be true
      nodeIntegration:              false,  // MUST be false
      sandbox:                      true,   // OS-level sandboxing
      webSecurity:                  true,   // same-origin (default; explicit)
      allowRunningInsecureContent:  false,
      experimentalFeatures:         false,
      // ── Preload bridge ─────────────────────────────────────────
      preload: path.join(__dirname, '..', 'preload', 'index.js'),
    },
  })

  // Show only once the DOM is fully painted (no white flash on load).
  mainWindow.once('ready-to-show', () => {
    mainWindow?.show()
  })

  // ── Load the renderer ──────────────────────────────────────────
  if (isDev) {
    // Vite dev server URL — must match vite.config.ts server.port
    mainWindow.loadURL('http://localhost:5173')
    mainWindow.webContents.openDevTools({ mode: 'detach' })
  } else {
    mainWindow.loadFile(path.join(__dirname, '..', '..', 'dist', 'index.html'))
  }

  // ── Navigation guard ───────────────────────────────────────────
  // Prevent the renderer from navigating to any URL other than the app origin.
  mainWindow.webContents.on('will-navigate', (event, url) => {
    const appURL = isDev ? 'http://localhost:5173' : `file://${path.join(__dirname, '..', '..', 'dist')}`
    if (!url.startsWith(appURL)) {
      event.preventDefault()
    }
  })

  // ── New-window guard ───────────────────────────────────────────
  // Block window.open() and <a target="_blank"> completely.
  // External links are handled by the 'open-external' IPC channel instead.
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    // Only allow opening https:// links in the system browser.
    if (url.startsWith('https://')) {
      shell.openExternal(url)
    }
    return { action: 'deny' }
  })

  mainWindow.on('closed', () => {
    mainWindow = null
  })
}

// ── Content Security Policy (session-level) ──────────────────────────────────
// Applied via HTTP response header — takes precedence over the meta-tag CSP.

function applyCSP(): void {
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': [
          [
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self' 'unsafe-inline'",  // Vite injects <style> tags
            "img-src 'self' data:",
            "font-src 'self' data:",
            "connect-src 'none'",
            "object-src 'none'",
            "base-uri 'none'",
            "frame-ancestors 'none'",
          ].join('; '),
        ],
      },
    })
  })
}

// ── Application menu (macOS) ─────────────────────────────────────────────────

function buildAppMenu(): void {
  const template: Electron.MenuItemConstructorOptions[] = [
    {
      label: app.name,
      submenu: [
        {
          label: `About ${app.name}`,
          click: () => {
            dialog.showMessageBox({
              type:    'info',
              title:   `About ${app.name}`,
              message: `${app.name}  v${APP_VERSION}`,
              detail:  '© 2026 CycloneDX Contributors\nhttps://github.com/CycloneDX/sbom-utility',
              buttons: ['OK'],
            })
          },
        },
        { type: 'separator' },
        { role: 'services' },
        { type: 'separator' },
        { role: 'hide' },
        { role: 'hideOthers' },
        { role: 'unhide' },
        { type: 'separator' },
        { role: 'quit' },
      ],
    },
    {
      label: 'File',
      submenu: [
        { role: process.platform === 'darwin' ? 'close' : 'quit' },
      ],
    },
    {
      label: 'Edit',
      submenu: [
        { role: 'undo' },
        { role: 'redo' },
        { type: 'separator' },
        { role: 'cut' },
        { role: 'copy' },
        { role: 'paste' },
        { role: 'selectAll' },
      ],
    },
    {
      label: 'View',
      submenu: [
        { role: 'resetZoom' },
        { role: 'zoomIn' },
        { role: 'zoomOut' },
        { type: 'separator' },
        { role: 'togglefullscreen' },
        ...(isDev ? [{ role: 'toggleDevTools' as const }] : []),
      ],
    },
    {
      label: 'Window',
      submenu: [
        { role: 'minimize' },
        { role: 'zoom' },
        { type: 'separator' },
        { role: 'front' },
      ],
    },
  ]
  const menu = Menu.buildFromTemplate(template)
  Menu.setApplicationMenu(menu)
}

// ── App lifecycle ─────────────────────────────────────────────────────────────

app.whenReady().then(() => {
  applyCSP()
  buildAppMenu()

  // Register all IPC handlers before the window loads.
  registerIpcHandlers({
    binaryPath:      resolveBinaryPath(),
    configPath:      resolveConfigPath(),
    licensePolicyPath: resolveLicensePolicyPath(),
  })

  createWindow()

  // macOS: re-create the window when the dock icon is clicked and no windows exist.
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit()
})

// ── IPC: file-open dialog ─────────────────────────────────────────────────────
// Kept here (not in ipc-handlers) because it needs access to BrowserWindow.

ipcMain.handle('dialog:openFile', async () => {
  const win = BrowserWindow.getFocusedWindow()
  if (!win) return null
  const result = await dialog.showOpenDialog(win, {
    title:      'Open BOM File',
    filters:    [{ name: 'BOM Files', extensions: ['json', 'xml'] }],
    properties: ['openFile'],
  })
  if (result.canceled || result.filePaths.length === 0) return null
  return result.filePaths[0]
})

// ── IPC: theme query ──────────────────────────────────────────────────────────

ipcMain.handle('app:isDarkMode', () => nativeTheme.shouldUseDarkColors)
ipcMain.handle('app:version',    () => APP_VERSION)
