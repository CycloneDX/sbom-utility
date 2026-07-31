// SPDX-License-Identifier: Apache-2.0
/**
 * OptionsPanel — collapsible side panel for command flags.
 * Mirrors the Fyne SidePanel / "▼ Title" toggle pattern.
 */
import { useState } from 'react'
import styles from './OptionsPanel.module.css'

interface Props {
  title:    string
  children: React.ReactNode
  defaultOpen?: boolean
}

export default function OptionsPanel({ title, children, defaultOpen = true }: Props) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <section className={styles.panel}>
      <button
        className={styles.toggle}
        onClick={() => setOpen(v => !v)}
        aria-expanded={open}
      >
        <span className={styles.arrow}>{open ? '▼' : '▶'}</span>
        {title}
      </button>
      {open && <div className={styles.body}>{children}</div>}
    </section>
  )
}
