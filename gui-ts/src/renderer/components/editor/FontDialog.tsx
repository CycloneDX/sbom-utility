// SPDX-License-Identifier: Apache-2.0
/**
 * FontDialog — modal for choosing the editor's font family and size.
 *
 * Opens when the user clicks "Font…" in the editor toolbar.
 * Calls onApply with the chosen EditorFont when the user confirms.
 */
import { useEffect, useRef, useState } from 'react'
import type { EditorFont } from '../../context/AppContext'
import styles from './FontDialog.module.css'

// ── Available font choices ────────────────────────────────────────────────────

const FONT_CHOICES: { label: string; value: string }[] = [
  { label: 'System Monospace',  value: 'ui-monospace, "Cascadia Code", "Fira Code", Consolas, "Courier New", monospace' },
  { label: 'Cascadia Code',     value: '"Cascadia Code", ui-monospace, Consolas, monospace' },
  { label: 'Fira Code',         value: '"Fira Code", ui-monospace, Consolas, monospace' },
  { label: 'Consolas',          value: 'Consolas, ui-monospace, "Courier New", monospace' },
  { label: 'Courier New',       value: '"Courier New", Courier, monospace' },
  { label: 'JetBrains Mono',    value: '"JetBrains Mono", ui-monospace, Consolas, monospace' },
  { label: 'Source Code Pro',   value: '"Source Code Pro", ui-monospace, Consolas, monospace' },
  { label: 'Menlo',             value: 'Menlo, ui-monospace, Consolas, monospace' },
]

const SIZE_PRESETS = [10, 11, 12, 13, 14, 16, 18, 20, 24]

// ── Component ─────────────────────────────────────────────────────────────────

interface Props {
  current:  EditorFont
  onApply:  (font: EditorFont) => void
  onCancel: () => void
}

export default function FontDialog({ current, onApply, onCancel }: Props) {
  const [family, setFamily] = useState(current.family)
  const [size,   setSize]   = useState(current.size)
  const dialogRef           = useRef<HTMLDivElement>(null)

  // Focus trap — close on Escape
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onCancel()
      if (e.key === 'Enter')  onApply({ family, size })
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [family, size, onApply, onCancel])

  // Focus dialog on mount
  useEffect(() => { dialogRef.current?.focus() }, [])

  function handleSizeInput(raw: string) {
    const n = parseInt(raw, 10)
    if (!isNaN(n) && n >= 8 && n <= 72) setSize(n)
  }

  return (
    <div className={styles.backdrop} onClick={onCancel}>
      <div
        className={styles.dialog}
        ref={dialogRef}
        tabIndex={-1}
        role="dialog"
        aria-label="Font settings"
        onClick={e => e.stopPropagation()}
      >
        <div className={styles.header}>
          <span className={styles.title}>Editor Font</span>
        </div>

        <div className={styles.body}>
          {/* Font family */}
          <label className={styles.label}>Font Family</label>
          <select
            className={styles.select}
            value={family}
            onChange={e => setFamily(e.target.value)}
          >
            {FONT_CHOICES.map(f => (
              <option key={f.label} value={f.value}>{f.label}</option>
            ))}
          </select>

          {/* Size row: preset buttons + numeric input */}
          <label className={styles.label} style={{ marginTop: 14 }}>Font Size (px)</label>
          <div className={styles.sizeRow}>
            {SIZE_PRESETS.map(s => (
              <button
                key={s}
                className={`${styles.sizeBtn}${size === s ? ' ' + styles.sizeBtnActive : ''}`}
                onClick={() => setSize(s)}
              >
                {s}
              </button>
            ))}
          </div>
          <input
            className={styles.sizeInput}
            type="number"
            min={8}
            max={72}
            value={size}
            onChange={e => handleSizeInput(e.target.value)}
          />

          {/* Preview */}
          <div className={styles.previewLabel}>Preview</div>
          <div
            className={styles.preview}
            style={{ fontFamily: family, fontSize: size }}
          >
            {`{ "specVersion": "1.5", "components": [ ] }`}
          </div>
        </div>

        <div className={styles.footer}>
          <button className={styles.cancelBtn} onClick={onCancel}>Cancel</button>
          <button className={styles.applyBtn}  onClick={() => onApply({ family, size })}>Apply</button>
        </div>
      </div>
    </div>
  )
}
