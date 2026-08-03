// SPDX-License-Identifier: Apache-2.0
import React, { createContext, useCallback, useContext, useRef, useState } from 'react'
import type { BomInfo } from '../../preload/index'

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
  bomFile:            string
  bomInfo:            BomInfo
  screen:             Screen
  version:            string
  editorFont:         EditorFont
  isDirty:            boolean
  validateBadge:      ValidateBadge
  validateBadgeText:  string
  autoValidateOnLoad: boolean
}

export interface AppContextValue extends AppState {
  setBomFile:            (path: string) => void
  setBomInfo:            (info: BomInfo) => void
  setScreen:             (screen: Screen) => void
  setEditorFont:         (font: EditorFont) => void
  setDirty:              (dirty: boolean) => void
  setValidateBadge:      (badge: ValidateBadge, text: string) => void
  setAutoValidateOnLoad: (enabled: boolean) => void
  // Listeners: other components can subscribe to bomFile changes
  onBomFileChange: (cb: (path: string) => void) => () => void
}

// ── Context ───────────────────────────────────────────────────────────────────

const AppContext = createContext<AppContextValue | null>(null)

function loadBool(key: string, fallback: boolean): boolean {
  try { const v = localStorage.getItem(key); return v === null ? fallback : v === 'true' } catch { return fallback }
}

export function AppProvider({ children, version }: { children: React.ReactNode; version: string }) {
  const [bomFile, setBomFileState]   = useState('')
  const [bomInfo, setBomInfo]        = useState<BomInfo>({ filePath: '', specVersion: '', format: '' })
  const [screen, setScreen]          = useState<Screen>('load')
  const [editorFont, setEditorFont]  = useState<EditorFont>(DEFAULT_EDITOR_FONT)
  const [isDirty, setDirty]          = useState(false)
  const [validateBadge, setValidateBadgeState]   = useState<ValidateBadge>('idle')
  const [validateBadgeText, setValidateBadgeText] = useState('')
  const [autoValidateOnLoad, setAutoValidateOnLoadState] = useState(() => loadBool('pref.autoValidateOnLoad', true))

  const setValidateBadge = useCallback((badge: ValidateBadge, text: string) => {
    setValidateBadgeState(badge)
    setValidateBadgeText(text)
  }, [])

  const setAutoValidateOnLoad = useCallback((enabled: boolean) => {
    setAutoValidateOnLoadState(enabled)
    try { localStorage.setItem('pref.autoValidateOnLoad', String(enabled)) } catch { /* ignore */ }
  }, [])

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

  const setBomFile = useCallback((path: string) => {
    setBomFileState(path)
    listeners.current.forEach(cb => cb(path))
  }, [])

  return (
    <AppContext.Provider value={{
      bomFile, bomInfo, screen, version, editorFont, isDirty,
      validateBadge, validateBadgeText, autoValidateOnLoad,
      setBomFile, setBomInfo, setScreen, setEditorFont, setDirty,
      setValidateBadge, setAutoValidateOnLoad, onBomFileChange,
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
