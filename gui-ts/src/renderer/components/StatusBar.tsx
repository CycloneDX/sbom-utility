// SPDX-License-Identifier: Apache-2.0
import { useAppContext } from '../context/AppContext'
import styles from './StatusBar.module.css'

/** Returns the basename portion of a path without importing Node's `path` module. */
function basename(p: string): string {
  return p.replace(/\\/g, '/').split('/').pop() ?? p
}

export default function StatusBar() {
  const { bomInfo, validateBadge, validateBadgeText } = useAppContext()
  const { format, specVersion, filePath } = bomInfo

  const base = filePath ? basename(filePath) : ''

  return (
    <footer className={styles.bar} role="status" aria-label="BOM status">
      {/* Left: validation badge */}
      {validateBadge !== 'idle' && (
        <span className={`${styles.validBadge} ${styles[`validBadge_${validateBadge}`]}`}>
          <span className={styles.validDot} />
          {validateBadgeText}
        </span>
      )}

      {/* Filename — full path shown on hover via title tooltip */}
      {filePath && (
        <span className={styles.filename} title={filePath}>
          {base}
        </span>
      )}
      {!filePath && (
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
