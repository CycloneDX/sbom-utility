// SPDX-License-Identifier: Apache-2.0
import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react'
import type { BomInfo, PreferencesResult } from '../../preload/index'

// ── Types ─────────────────────────────────────────────────────────────────────

export type Screen =
  | 'load'
  | 'validate'
  | 'licenses'
  | 'components'
  | 'resources'
  | 'vulnerabilities'
  | 'diff'
  | 'patch'
  | 'settings'

export type ValidateBadge = 'idle' | 'valid' | 'invalid'

export interface EditorFont {
  family: string
  size:   number   // in px (e.g. 13 = 13px ≈ 10pt on 96dpi, or just treat as px)
}

export const DEFAULT_EDITOR_FONT: EditorFont = {
  family: 'ui-monospace, "Cascadia Code", "Fira Code", Consolas, "Courier New", monospace',
  size:   13,   // ~11pt on macOS / 96 dpi screens
}

export interface AppState {
  bomFile:             string
  /** User-visible label for the loaded file (may differ from bomFile in browser
   *  mode where the browser cannot expose the real filesystem path). */
  bomDisplayName:      string
  bomInfo:             BomInfo
  screen:              Screen
  version:             string
  /** Persisted default font for all editor/results areas. Set via Preferences. */
  defaultEditorFont:   EditorFont
  defaultBomDirectory: string
  isDirty:             boolean
  validateBadge:       ValidateBadge
  validateBadgeText:   string
  autoValidateOnLoad:  boolean
  preferencesPath:     string
  preferencesExists:   boolean
}

export interface AppContextValue extends AppState {
  setBomFile:             (path: string, displayName?: string) => void
  setBomInfo:             (info: BomInfo) => void
  setScreen:              (screen: Screen) => void
  /** Updates the persisted default font (Preferences). Does NOT override the
   *  per-session font inside an open editor — each JsonEditor manages that
   *  independently via its own local state. */
  setDefaultEditorFont:   (font: EditorFont) => void
  setDefaultBomDirectory: (dir: string) => void
  setDirty:               (dirty: boolean) => void
  setValidateBadge:       (badge: ValidateBadge, text: string) => void
  setAutoValidateOnLoad:  (enabled: boolean) => void
  saveServerPreferences:  (font?: EditorFont, autoValidate?: boolean, bomDir?: string) => Promise<void>
  // Listeners: other components can subscribe to bomFile changes
  onBomFileChange: (cb: (path: string) => void) => () => void
}

// ── Context ───────────────────────────────────────────────────────────────────

const AppContext = createContext<AppContextValue | null>(null)

function loadBool(key: string, fallback: boolean): boolean {
  try { const v = localStorage.getItem(key); return v === null ? fallback : v === 'true' } catch { return fallback }
}

function loadEditorFont(): EditorFont {
  try {
    const raw = localStorage.getItem('pref.editorFont')
    if (raw) {
      const parsed = JSON.parse(raw) as Partial<EditorFont>
      if (typeof parsed.family === 'string' && typeof parsed.size === 'number') {
        return { family: parsed.family, size: parsed.size }
      }
    }
  } catch { /* ignore */ }
  return DEFAULT_EDITOR_FONT
}

export function AppProvider({ children, version }: { children: React.ReactNode; version: string }) {
  const [bomFile, setBomFileState]        = useState('')
  const [bomDisplayName, setBomDisplayName] = useState('')
  const [bomInfo, setBomInfo]             = useState<BomInfo>({ filePath: '', specVersion: '', format: '' })
  const [screen, setScreen]          = useState<Screen>('load')
  const [defaultEditorFont, setDefaultEditorFontState] = useState<EditorFont>(loadEditorFont)
  const [defaultBomDirectory, setDefaultBomDirectoryState] = useState<string>(() => {
    try { return localStorage.getItem('pref.defaultBomDirectory') || '' } catch { return '' }
  })
  const [isDirty, setDirty]          = useState(false)
  const [validateBadge, setValidateBadgeState]   = useState<ValidateBadge>('idle')
  const [validateBadgeText, setValidateBadgeText] = useState('')
  const [autoValidateOnLoad, setAutoValidateOnLoadState] = useState(() => loadBool('pref.autoValidateOnLoad', true))
  const [preferencesPath, setPreferencesPath] = useState('./preferences.json')
  const [preferencesExists, setPreferencesExists] = useState(false)

  // Load preferences from the backend on mount
  useEffect(() => {
    if (window.sbomBridge?.getPreferences) {
      window.sbomBridge.getPreferences().then((res: PreferencesResult) => {
        if (res) {
          setPreferencesPath(res.path)
          setPreferencesExists(res.exists)
          if (res.exists && res.preferences) {
            const fontFam = res.preferences.ui?.editorFontFamily || res.preferences.editorFontFamily
            const fontSize = res.preferences.ui?.editorFontSize || res.preferences.editorFontSize
            const autoVal = res.preferences.ui?.autoValidateOnLoad !== undefined
              ? res.preferences.ui.autoValidateOnLoad
              : res.preferences.autoValidateOnLoad
            const bomDir = res.preferences.ui?.defaultBomDirectory || res.preferences.defaultBomDirectory

            if (fontFam && fontSize) {
              const font: EditorFont = {
                family: fontFam,
                size: fontSize,
              }
              setDefaultEditorFontState(font)
              try { localStorage.setItem('pref.editorFont', JSON.stringify(font)) } catch { /* ignore */ }
            }
            if (typeof autoVal === 'boolean') {
              setAutoValidateOnLoadState(autoVal)
              try { localStorage.setItem('pref.autoValidateOnLoad', String(autoVal)) } catch { /* ignore */ }
            }
            if (typeof bomDir === 'string') {
              setDefaultBomDirectoryState(bomDir)
              try { localStorage.setItem('pref.defaultBomDirectory', bomDir) } catch { /* ignore */ }
            }
          }
        }
      }).catch(() => {
        /* fallback to localStorage */
      })
    }
  }, [])

  const setValidateBadge = useCallback((badge: ValidateBadge, text: string) => {
    setValidateBadgeState(badge)
    setValidateBadgeText(text)
  }, [])

  // Keep CSS variables in sync with the default font so every global consumer
  // (ResultsView, StatusBar) picks up the change automatically.
  useEffect(() => {
    const root = document.documentElement
    root.style.setProperty('--editor-font-family', defaultEditorFont.family)
    root.style.setProperty('--editor-font-size',   `${defaultEditorFont.size}px`)
  }, [defaultEditorFont])

  const saveServerPreferences = useCallback(async (font?: EditorFont, autoValidate?: boolean, bomDir?: string) => {
    const targetFont = font ?? defaultEditorFont
    const targetAutoValidate = autoValidate !== undefined ? autoValidate : autoValidateOnLoad
    const targetBomDir = bomDir !== undefined ? bomDir : defaultBomDirectory

    if (window.sbomBridge?.savePreferences) {
      try {
        const res = await window.sbomBridge.savePreferences({
          ui: {
            defaultBomDirectory: targetBomDir,
            editorFontFamily: targetFont.family,
            editorFontSize: targetFont.size,
            autoValidateOnLoad: targetAutoValidate,
          },
          defaultBomDirectory: targetBomDir,
          editorFontFamily: targetFont.family,
          editorFontSize: targetFont.size,
          autoValidateOnLoad: targetAutoValidate,
        })
        if (res) {
          setPreferencesPath(res.path)
          setPreferencesExists(res.exists)
        }
      } catch (err) {
        console.error('Failed to save preferences to server:', err)
      }
    }
  }, [defaultEditorFont, autoValidateOnLoad, defaultBomDirectory])

  const setDefaultEditorFont = useCallback((font: EditorFont) => {
    setDefaultEditorFontState(font)
    try { localStorage.setItem('pref.editorFont', JSON.stringify(font)) } catch { /* ignore */ }
    saveServerPreferences(font, undefined, undefined).catch(() => {})
  }, [saveServerPreferences])

  const setDefaultBomDirectory = useCallback((dir: string) => {
    setDefaultBomDirectoryState(dir)
    try { localStorage.setItem('pref.defaultBomDirectory', dir) } catch { /* ignore */ }
    saveServerPreferences(undefined, undefined, dir).catch(() => {})
  }, [saveServerPreferences])

  const setAutoValidateOnLoad = useCallback((enabled: boolean) => {
    setAutoValidateOnLoadState(enabled)
    try { localStorage.setItem('pref.autoValidateOnLoad', String(enabled)) } catch { /* ignore */ }
    saveServerPreferences(undefined, enabled, undefined).catch(() => {})
  }, [saveServerPreferences])

  // Listeners registry — use a ref so callbacks registered in effects don't
  // trigger re-renders of the provider on every setBomFile call.
  const listeners = useRef<Array<(path: string) => void>>([])

  const onBomFileChange = useCallback((cb: (path: string) => void) => {
    listeners.current.push(cb)
    // Return unsubscribe function
    return () => {
      listeners.current = listeners.current.filter(fn => fn !== cb)
    }
  }, [])

  const setBomFile = useCallback((path: string, displayName?: string) => {
    setBomFileState(path)
    setBomDisplayName(displayName ?? path)
    listeners.current.forEach(cb => cb(path))
  }, [])

  return (
    <AppContext.Provider value={{
      bomFile, bomDisplayName, bomInfo, screen, version, defaultEditorFont, defaultBomDirectory, isDirty,
      validateBadge, validateBadgeText, autoValidateOnLoad, preferencesPath, preferencesExists,
      setBomFile, setBomInfo, setScreen, setDefaultEditorFont, setDefaultBomDirectory, setDirty,
      setValidateBadge, setAutoValidateOnLoad, saveServerPreferences, onBomFileChange,
    }}>
      {children}
    </AppContext.Provider>
  )
}

export function useAppContext(): AppContextValue {
  const ctx = useContext(AppContext)
  if (!ctx) throw new Error('useAppContext must be used inside AppProvider')
  return ctx
}
