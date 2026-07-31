// SPDX-License-Identifier: Apache-2.0
import { useEffect } from 'react'
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
import styles from './Shell.module.css'
import type { BomInfo } from '../../preload/index'

const SCREENS: Screen[] = [
  'load', 'view', 'validate', 'licenses',
  'components', 'resources', 'vulnerabilities',
]

export default function Shell() {
  const { screen, setScreen, bomFile, setBomFile, setBomInfo } = useAppContext()

  // When the user loads a BOM, auto-switch to View
  useEffect(() => {
    if (bomFile) setScreen('view')
  }, [bomFile, setScreen])

  const handleLoad = async () => {
    const path = await window.sbomBridge.openFile()
    if (!path) return
    setBomFile(path)
    // Fetch BOM metadata asynchronously for the status bar
    window.sbomBridge.getBomInfo(path)
      .then((info: BomInfo) => setBomInfo(info))
      .catch(() => {/* non-fatal */})
  }

  return (
    <div className={styles.shell}>
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
            </div>
          ))}
        </main>
      </div>
      <StatusBar />
    </div>
  )
}
