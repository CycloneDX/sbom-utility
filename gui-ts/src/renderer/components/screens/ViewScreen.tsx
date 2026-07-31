// SPDX-License-Identifier: Apache-2.0
import { useEffect, useState } from 'react'
import { useAppContext } from '../../context/AppContext'
import styles from './Screen.module.css'

export default function ViewScreen() {
  const { bomFile } = useAppContext()
  const [text,    setText]    = useState('')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (!bomFile) { setText(''); return }
    setLoading(true)
    window.sbomBridge.readFile(bomFile)
      .then((t: string) => { setText(t); setLoading(false) })
      .catch((e: Error) => { setText(`[ERROR] ${e?.message ?? String(e)}`); setLoading(false) })
  }, [bomFile])

  return (
    <div className={styles.screen}>
      <div className={styles.pathLabel}>
        {bomFile ? `Loaded: ${bomFile}` : 'No file loaded — click "Load BOM" in the sidebar.'}
      </div>
      <div className="viewer-pane flex-1">
        {loading ? (
          <div style={{ padding: 'var(--space-6)', color: 'var(--viewer-ph)', fontStyle: 'italic' }}>
            Reading file…
          </div>
        ) : (
          <pre className="selectable" style={{
            fontFamily: 'var(--font-mono)',
            fontSize:   12,
            lineHeight: 'var(--leading-normal)',
            whiteSpace: 'pre-wrap',
            wordBreak:  'break-all',
            padding:    'var(--space-4)',
            margin:     0,
            color:      text ? 'var(--viewer-fg)' : 'var(--viewer-ph)',
            fontStyle:  text ? 'normal' : 'italic',
          }}>
            {text || 'No BOM file loaded — click "Load BOM" in the sidebar.'}
          </pre>
        )}
      </div>
    </div>
  )
}
