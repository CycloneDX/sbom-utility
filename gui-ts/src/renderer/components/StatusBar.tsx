// SPDX-License-Identifier: Apache-2.0
import { useAppContext } from '../context/AppContext'
import styles from './StatusBar.module.css'

export default function StatusBar() {
  const { bomDisplayName, bomInfo, validateBadge, validateBadgeText } = useAppContext()
  const { format, specVersion, filePath } = bomInfo

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

      {/* Subtle separator between filename and format/version */}
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
