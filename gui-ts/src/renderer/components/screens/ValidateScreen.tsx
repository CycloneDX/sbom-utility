// SPDX-License-Identifier: Apache-2.0
import { useEffect, useState } from 'react'
import { useAppContext } from '../../context/AppContext'
import OptionsPanel from '../OptionsPanel'
import ResultsView  from '../ResultsView'
import styles from './Screen.module.css'

type BadgeState = 'idle' | 'valid' | 'invalid'

const DEFAULT_MAX_ERRORS = 10

interface Props { active: boolean }

export default function ValidateScreen({ active }: Props) {
  const { bomFile } = useAppContext()

  const [output,    setOutput]    = useState('')
  const [loading,   setLoading]   = useState(false)
  const [badge,     setBadge]     = useState<BadgeState>('idle')
  const [badgeText, setBadgeText] = useState('')
  const [dirty,     setDirty]     = useState(true)

  // Options
  const [variant,    setVariant]    = useState('')
  const [force,      setForce]      = useState('')
  const [maxErrors,  setMaxErrors]  = useState(String(DEFAULT_MAX_ERRORS))
  const [showValues, setShowValues] = useState(true)

  const markDirty = () => setDirty(true)

  const run = async () => {
    if (!bomFile) return
    setLoading(true)
    setOutput('')
    setBadge('idle')
    setDirty(false)
    try {
      const res = await window.sbomBridge.validate({
        filePath:    bomFile,
        variant:     variant || undefined,
        forceSchema: force   || undefined,
        maxErrors:   parseInt(maxErrors, 10) || DEFAULT_MAX_ERRORS,
        showValues,
      })
      const combined = res.stdout + (res.stderr ? '\n' + res.stderr : '')
      setOutput(combined || 'BOM document is VALID — no schema errors found.')
      if (res.code === 0) {
        setBadge('valid'); setBadgeText('VALID')
      } else {
        setBadge('invalid')
        const firstLine = (res.stderr || res.stdout).split('\n')[0] ?? ''
        setBadgeText(`INVALID${firstLine ? ' — ' + firstLine : ''}`)
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e)
      setOutput(`[ERROR] ${msg}`)
      setBadge('invalid'); setBadgeText('ERROR')
    } finally {
      setLoading(false)
    }
  }

  // Auto-run when this screen becomes active and a BOM is loaded
  useEffect(() => { if (active && bomFile) { run() } }, [active, bomFile])

  return (
    <div className={styles.screen}>
      {/* ── Status badge bar ─────────────────────────── */}
      <div className={styles.topBar}>
        <span className={`badge badge-${badge}`}>
          <span className="badge-dot" />
          {badge === 'idle' ? 'Not yet run' : badgeText}
        </span>
      </div>

      <div className={styles.split}>
        {/* ── Options column ─────────────────────────── */}
        <div className={styles.options}>
          <OptionsPanel title="Validate Options">
            <div className="flag-row">
              <label className="flag-label">Schema variant (--variant):</label>
              <input
                className="input"
                value={variant}
                onChange={e => { setVariant(e.target.value); markDirty() }}
                placeholder="e.g. strict  (blank = auto)"
              />
            </div>
            <div className="flag-row">
              <label className="flag-label">Force schema file (--force):</label>
              <input
                className="input"
                value={force}
                onChange={e => { setForce(e.target.value); markDirty() }}
                placeholder="path/to/schema.json  (blank = auto)"
              />
            </div>
            <div className="flag-row">
              <label className="flag-label">Max errors shown (--error-limit):</label>
              <input
                className="input"
                type="number"
                min={1} max={200}
                value={maxErrors}
                onChange={e => { setMaxErrors(e.target.value); markDirty() }}
              />
            </div>
            <label className="checkbox-row">
              <input
                type="checkbox"
                checked={showValues}
                onChange={e => { setShowValues(e.target.checked); markDirty() }}
              />
              Show failing values in errors
            </label>
            <div className="separator" />
            <button
              className="btn btn-primary w-full"
              onClick={run}
              disabled={loading || !bomFile || !dirty}
            >
              ✅ &nbsp;{loading ? 'Validating…' : 'Validate'}
            </button>
          </OptionsPanel>
        </div>

        {/* ── Results column ─────────────────────────── */}
        <div className={styles.results}>
          <ResultsView text={output} loading={loading} />
        </div>
      </div>
    </div>
  )
}
