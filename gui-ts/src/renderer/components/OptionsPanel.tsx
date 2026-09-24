// SPDX-License-Identifier: Apache-2.0
/**
 * OptionsPanel — side panel for command flags.
 * The title bar is styled like a dialog window title bar (solid accent
 * background, white text) and is purely decorative — the panel is always open.
 *
 * Props:
 *   action  — node rendered in the gray footer zone (the execute button)
 *   notice  — short string shown in an amber banner between the title and
 *             the body; used to signal "no changes to apply" without disabling
 *             the button
 */
import styles from './OptionsPanel.module.css'

interface Props {
  title:    string
  children: React.ReactNode
  action?:  React.ReactNode
  notice?:  string
}

export default function OptionsPanel({ title, children, action, notice }: Props) {
  return (
    <section className={styles.panel}>
      <div className={styles.titlebar}>{title}</div>
      <div className={styles.notice}>{notice ? `⚠ ${notice}` : ''}</div>
      <div className={styles.body}>{children}</div>
      {action && <div className={styles.footer}>{action}</div>}
    </section>
  )
}
