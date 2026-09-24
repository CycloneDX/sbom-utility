// SPDX-License-Identifier: Apache-2.0
import { useAppContext } from '../context/AppContext'
import styles from './StatusBar.module.css'

export default function StatusBar() {
  const {
    bomDisplayName,
    bomInfo,
    validateBadge,
    validateBadgeText,
    preferencesPath,
    preferencesExists,
    setScreen,
  } = useAppContext()
  const { format, specVersion, filePath } = bomInfo

  // Short label for the preferences file name
  const prefFilename = preferencesPath.split(/[/\\]/).pop() || 'preferences.json'
  const prefTooltip = `Preferences: ${preferencesPath}\nStatus: ${preferencesExists ? 'Loaded from file' : 'Default (file not created)'}\nClick to configure preferences`

  return (
    <footer className={styles.bar} role="status" aria-label="BOM status">
      {/* Left: validation badge */}
      {validateBadge !== 'idle' && (
        <span className={`${styles.validBadge} ${styles[`validBadge_${validateBadge}`]}`}>
          <span className={styles.validDot} />
          {validateBadgeText}
        </span>
      )}

      {/* Filename — user-visible name from file picker (full path in Electron;
          basename only in browser mode where the sandbox hides the full path).
          Tooltip shows the internal filePath for debugging. */}
      {bomDisplayName && (
        <span className={styles.filename} title={filePath || bomDisplayName}>
          {bomDisplayName}
        </span>
      )}
      {!bomDisplayName && (
        <span className={styles.filename} style={{ opacity: 0.4 }}>
          No BOM loaded
        </span>
      )}

      {/* Interactive Preferences item */}
      <span className={styles.sep} aria-hidden="true" />
      <button
        type="button"
        className={styles.itemButton}
        onClick={() => setScreen('settings')}
        title={prefTooltip}
        aria-label="Open preferences"
      >
        <span>⚙️</span>
        <span className={styles.prefName}>{prefFilename}</span>
        <span className={styles.prefStatus}>{preferencesExists ? '(loaded)' : '(default)'}</span>
      </button>

      {/* Subtle separator between preferences and format/version */}
      {(format || specVersion) && <span className={styles.sep} aria-hidden="true" />}

      {/* Format + Version — right of separator */}
      {format && (
        <span className={styles.segment}>
          <span className={styles.label}>Format:</span>
          <span className={styles.value}>{format}</span>
        </span>
      )}
      {specVersion && (
        <span className={styles.segment}>
          <span className={styles.label}>Version:</span>
          <span className={styles.value}>{specVersion}</span>
        </span>
      )}
    </footer>
  )
}
