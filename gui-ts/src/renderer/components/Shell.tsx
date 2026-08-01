// SPDX-License-Identifier: Apache-2.0
import { useEffect, useRef, useState } from 'react'
import { useAppContext, type Screen } from '../context/AppContext'
import Sidebar   from './Sidebar'
import StatusBar from './StatusBar'
import LoadScreen          from './screens/LoadScreen'
import ViewScreen          from './screens/ViewScreen'
import ValidateScreen      from './screens/ValidateScreen'
import LicenseScreen       from './screens/LicenseScreen'
import ComponentScreen     from './screens/ComponentScreen'
import ResourceScreen      from './screens/ResourceScreen'
import VulnerabilityScreen from './screens/VulnerabilityScreen'
import DiffScreen          from './screens/DiffScreen'
import PatchScreen         from './screens/PatchScreen'
import styles from './Shell.module.css'
import type { BomInfo } from '../../preload/index'

const SCREENS: Screen[] = [
  'load', 'view', 'validate', 'licenses',
  'components', 'resources', 'vulnerabilities',
  'diff', 'patch',
]

export default function Shell() {
  const { screen, setScreen, bomFile, setBomFile, setBomInfo, isDirty, setDirty } = useAppContext()

  // When the user loads a BOM, auto-switch to View
  useEffect(() => {
    if (bomFile) setScreen('view')
  }, [bomFile, setScreen])

  // ── Unsaved-changes guard ─────────────────────────────────────────────────
  const [showDirtyWarning, setShowDirtyWarning] = useState(false)
  const pendingLoad = useRef<(() => Promise<void>) | null>(null)

  async function doLoad() {
    const path = await window.sbomBridge.openFile()
    if (!path) return
    setDirty(false)
    setBomFile(path)
    // Fetch BOM metadata asynchronously for the status bar
    window.sbomBridge.getBomInfo(path)
      .then((info: BomInfo) => setBomInfo(info))
      .catch(() => {/* non-fatal */})
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
              {s === 'view'            && <ViewScreen />}
              {s === 'validate'        && <ValidateScreen active={screen === 'validate'} />}
              {s === 'licenses'        && <LicenseScreen active={screen === 'licenses'} />}
              {s === 'components'      && <ComponentScreen active={screen === 'components'} />}
              {s === 'resources'       && <ResourceScreen active={screen === 'resources'} />}
              {s === 'vulnerabilities' && <VulnerabilityScreen active={screen === 'vulnerabilities'} />}
              {s === 'diff'            && <DiffScreen active={screen === 'diff'} />}
              {s === 'patch'           && <PatchScreen active={screen === 'patch'} />}
            </div>
          ))}
        </main>
      </div>
      <StatusBar />
    </div>
  )
}
