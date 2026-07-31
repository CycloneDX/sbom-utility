// SPDX-License-Identifier: Apache-2.0
import { Fragment } from 'react'
import type { Screen } from '../context/AppContext'
import { useAppContext } from '../context/AppContext'
import styles from './Sidebar.module.css'

interface NavEntry {
  screen:  Screen
  label:   string
  icon:    string
  section?: string  // optional section separator label before this item
  requireBom: boolean
}

const NAV_ENTRIES: NavEntry[] = [
  { screen: 'view',            label: 'View',            icon: '📄', requireBom: true,  section: 'BOM Tools' },
  { screen: 'validate',        label: 'Validate',        icon: '✅', requireBom: true  },
  { screen: 'licenses',        label: 'Licenses',        icon: 'ℹ️',  requireBom: true  },
  { screen: 'components',      label: 'Components',      icon: '📦', requireBom: true  },
  { screen: 'resources',       label: 'Resources',       icon: '🗄️',  requireBom: true  },
  { screen: 'vulnerabilities', label: 'Vulnerabilities', icon: '⚠️', requireBom: true  },
]

interface Props {
  activeScreen: Screen
  bomLoaded:    boolean
  onNav:        (screen: Screen) => void
  onLoadBOM:    () => void
}

export default function Sidebar({ activeScreen, bomLoaded, onNav, onLoadBOM }: Props) {
  const { version } = useAppContext()

  return (
    <nav className={styles.sidebar} aria-label="Application navigation">
      {/* ── App header ──────────────────────────────── */}
      <div className={styles.header}>
        <div className={styles.appName}>SBOM Utility</div>
        <div className={styles.appSub}>v{version} · CycloneDX</div>
      </div>

      {/* ── Load BOM ───────────────────────────────── */}
      <button
        className={`${styles.navItem} ${activeScreen === 'load' ? styles.active : ''}`}
        onClick={onLoadBOM}
        aria-label="Open a BOM file"
      >
        <span className={styles.icon}>📂</span>
        Load BOM
      </button>

      <div className={styles.sectionLabel}>Analysis</div>

      {/* ── Tool nav buttons ───────────────────────── */}
      {NAV_ENTRIES.map(entry => (
        <Fragment key={entry.screen}>
          {entry.section && entry.screen !== 'view' && (
            <div className={styles.sectionLabel}>{entry.section}</div>
          )}
          <button
            className={`${styles.navItem} ${activeScreen === entry.screen ? styles.active : ''}`}
            disabled={entry.requireBom && !bomLoaded}
            onClick={() => onNav(entry.screen)}
            aria-current={activeScreen === entry.screen ? 'page' : undefined}
            title={entry.requireBom && !bomLoaded ? 'Load a BOM file first' : entry.label}
          >
            <span className={styles.icon}>{entry.icon}</span>
            {entry.label}
          </button>
        </Fragment>
      ))}
    </nav>
  )
}
