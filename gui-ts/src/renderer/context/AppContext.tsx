// SPDX-License-Identifier: Apache-2.0
import React, { createContext, useCallback, useContext, useRef, useState } from 'react'
import type { BomInfo } from '../../preload/index'

// ── Types ─────────────────────────────────────────────────────────────────────

export type Screen =
  | 'load'
  | 'view'
  | 'validate'
  | 'licenses'
  | 'components'
  | 'resources'
  | 'vulnerabilities'
  | 'diff'
  | 'patch'

export interface AppState {
  bomFile:     string
  bomInfo:     BomInfo
  screen:      Screen
  version:     string
}

export interface AppContextValue extends AppState {
  setBomFile:  (path: string) => void
  setBomInfo:  (info: BomInfo) => void
  setScreen:   (screen: Screen) => void
  // Listeners: other components can subscribe to bomFile changes
  onBomFileChange: (cb: (path: string) => void) => () => void
}

// ── Context ───────────────────────────────────────────────────────────────────

const AppContext = createContext<AppContextValue | null>(null)

export function AppProvider({ children, version }: { children: React.ReactNode; version: string }) {
  const [bomFile, setBomFileState] = useState('')
  const [bomInfo, setBomInfo]      = useState<BomInfo>({ filePath: '', specVersion: '', format: '' })
  const [screen, setScreen]        = useState<Screen>('load')

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
      bomFile, bomInfo, screen, version,
      setBomFile, setBomInfo, setScreen, onBomFileChange,
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
