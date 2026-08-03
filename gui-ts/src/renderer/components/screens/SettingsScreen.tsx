// SPDX-License-Identifier: Apache-2.0
import { useAppContext } from '../../context/AppContext'
import styles from './Screen.module.css'

export default function SettingsScreen() {
  const { autoValidateOnLoad, setAutoValidateOnLoad } = useAppContext()

  return (
    <div className={styles.screen} style={{ padding: 'var(--space-6)' }}>
      <h2 style={{ marginBottom: 'var(--space-4)' }}>Preferences</h2>

      {/* ── Validation ───────────────────────────────── */}
      <section style={{ marginBottom: 'var(--space-6)' }}>
        <h3 style={{ marginBottom: 'var(--space-3)', color: 'var(--color-text-muted)', fontSize: 'var(--text-xs)', fontWeight: 'var(--weight-bold)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
          Validation
        </h3>

        <label className="checkbox-row" style={{ userSelect: 'none' }}>
          <input
            type="checkbox"
            checked={autoValidateOnLoad}
            onChange={e => setAutoValidateOnLoad(e.target.checked)}
          />
          <span>
            <strong>Auto-validate on BOM load</strong>
            <br />
            <span className="text-caption">
              Runs validation silently in the background whenever a new BOM file is opened.
              The result is shown in the status bar at the bottom of the window.
            </span>
          </span>
        </label>
      </section>

      {/* ── About ─────────────────────────────────────── */}
      <section>
        <h3 style={{ marginBottom: 'var(--space-3)', color: 'var(--color-text-muted)', fontSize: 'var(--text-xs)', fontWeight: 'var(--weight-bold)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
          About
        </h3>
        <p className="text-muted">
          SBOM Utility GUI — powered by CycloneDX sbom-utility.
        </p>
      </section>
    </div>
  )
}
