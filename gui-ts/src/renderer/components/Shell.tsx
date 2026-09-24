// SPDX-License-Identifier: Apache-2.0
import { useEffect, useRef, useState } from 'react'
import { useAppContext, type Screen } from '../context/AppContext'
import Sidebar       from './Sidebar'
import StatusBar     from './StatusBar'
import LoadScreen          from './screens/LoadScreen'
import ValidateScreen      from './screens/ValidateScreen'
import LicenseScreen       from './screens/LicenseScreen'
import ComponentScreen     from './screens/ComponentScreen'
import ResourceScreen      from './screens/ResourceScreen'
import VulnerabilityScreen from './screens/VulnerabilityScreen'
import DiffScreen          from './screens/DiffScreen'
import PatchScreen         from './screens/PatchScreen'
import SettingsScreen      from './screens/SettingsScreen'
import styles from './Shell.module.css'
import type { BomInfo } from '../../preload/index'

const SCREENS: Screen[] = [
  'load', 'validate', 'licenses',
  'components', 'resources', 'vulnerabilities',
  'diff', 'patch', 'settings',
]

export default function Shell() {
  const {
    screen, setScreen, bomFile, setBomFile, setBomInfo, isDirty, setDirty,
    setValidateBadge,
  } = useAppContext()

  // When the user loads a BOM, auto-switch to View/Validate
  useEffect(() => {
    if (bomFile) setScreen('validate')
  }, [bomFile, setScreen])

  // ── Unsaved-changes guard ─────────────────────────────────────────────────
  const [showDirtyWarning, setShowDirtyWarning] = useState(false)
  const pendingLoad = useRef<(() => Promise<void>) | null>(null)

  async function doLoad() {
    const result = await window.sbomBridge.openFile()
    if (!result) return
    setDirty(false)
    // Reset badge so the status bar shows "Running…" while ValidateScreen runs
    setValidateBadge('idle', '')
    setBomFile(result.path, result.displayName)
    // Fetch BOM metadata asynchronously for the status bar
    window.sbomBridge.getBomInfo(result.path)
      .then((info: BomInfo) => setBomInfo(info))
      .catch(() => {/* non-fatal */})
    // ValidateScreen handles auto-validation via its own useEffect when it
    // becomes the active screen (triggered by setBomFile above).  Issuing a
    // second concurrent validate call here races on shared global state in the
    // Go server and produces inconsistent badge / output results.
  }

  const handleLoad = () => {
    if (isDirty) {
      pendingLoad.current = doLoad
      setShowDirtyWarning(true)
    } else {
      doLoad()
    }
  }

  function handleDirtyConfirm() {
    setShowDirtyWarning(false)
    pendingLoad.current?.()
    pendingLoad.current = null
  }

  function handleDirtyCancel() {
    setShowDirtyWarning(false)
    pendingLoad.current = null
  }

  return (
    <div className={styles.shell}>
      {/* ── Unsaved-changes warning ──────────────────────────────────────────── */}
      {showDirtyWarning && (
        <div className={styles.dirtyWarning}>
          <span className={styles.dirtyWarningText}>
            ⚠ You have unsaved edits. Loading a new BOM will discard them.
          </span>
          <button className={styles.dirtyDiscardBtn} onClick={handleDirtyConfirm}>
            Discard &amp; Load
          </button>
          <button className={styles.dirtyCancelBtn} onClick={handleDirtyCancel}>
            Cancel
          </button>
        </div>
      )}
      <div className={styles.body}>
        <Sidebar
          activeScreen={screen}
          bomLoaded={bomFile !== ''}
          onNav={setScreen}
          onLoadBOM={handleLoad}
        />
        <main className={styles.content}>
          {SCREENS.map(s => (
            <div key={s} style={{ display: screen === s ? 'flex' : 'none', flex: 1, flexDirection: 'column', minHeight: 0 }}>
              {s === 'load'            && <LoadScreen onLoad={handleLoad} />}
              {s === 'validate'        && <ValidateScreen active={screen === 'validate'} />}
              {s === 'licenses'        && <LicenseScreen active={screen === 'licenses'} />}
              {s === 'components'      && <ComponentScreen active={screen === 'components'} />}
              {s === 'resources'       && <ResourceScreen active={screen === 'resources'} />}
              {s === 'vulnerabilities' && <VulnerabilityScreen active={screen === 'vulnerabilities'} />}
              {s === 'diff'            && <DiffScreen active={screen === 'diff'} />}
              {s === 'patch'           && <PatchScreen active={screen === 'patch'} />}
              {s === 'settings'        && <SettingsScreen />}
            </div>
          ))}
        </main>
      </div>
      <StatusBar />
    </div>
  )
}
