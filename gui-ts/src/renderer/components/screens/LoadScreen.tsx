// SPDX-License-Identifier: Apache-2.0

import styles from './Screen.module.css'

interface Props {
  onLoad: () => void
}

export default function LoadScreen({ onLoad }: Props) {
  return (
    <div className={styles.screen} style={{ alignItems: 'center', justifyContent: 'center', gap: 'var(--space-6)' }}>
      <div style={{ textAlign: 'center' }}>
        <div style={{ fontSize: 56, lineHeight: 1 }}>📂</div>
        <h2 style={{ marginTop: 'var(--space-4)', marginBottom: 'var(--space-2)' }}>
          CycloneDX SBOM Utility
        </h2>
        <p className="text-muted" style={{ maxWidth: 340, textAlign: 'center', lineHeight: 'var(--leading-loose)' }}>
          Open a BOM file (<code>.json</code> or <code>.xml</code>) to validate,
          inspect licenses, components, resources, and vulnerabilities.
        </p>
      </div>
      <button className="btn btn-primary" onClick={onLoad} style={{ fontSize: 'var(--text-md)', height: 40, padding: '0 var(--space-8)' }}>
        📂 &nbsp; Load BOM File…
      </button>
      <p className="text-caption" style={{ textAlign: 'center' }}>
        You can also click <strong>Load BOM</strong> in the sidebar at any time.
      </p>
    </div>
  )
}
