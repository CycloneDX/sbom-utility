// SPDX-License-Identifier: Apache-2.0
/**
 * PatchScreen — apply a JSON patch to a CycloneDX BOM using `sbom-utility patch`.
 *
 * Layout: options panel (left) | before/after split (right)
 * The right pane shows the original BOM (top) and patched output (bottom),
 * both rendered by DiffHighlighter so changes are colour-coded.
 */
import { useState, useCallback, useEffect } from 'react'
import { useAppContext } from '../../context/AppContext'
import JsonEditor from '../editor/JsonEditor'
import DiffHighlighter from '../editor/DiffHighlighter'
import styles from './Screen.module.css'
import type { RunResult } from '../../../preload/index'

interface Props {
  active: boolean
}

export default function PatchScreen({ active: _active }: Props) {
  const { bomFile } = useAppContext()

  const [bomPath,   setBomPath]   = useState(bomFile)
  const [patchPath, setPatchPath] = useState('')
  const [origText,  setOrigText]  = useState('')
  const [result,    setResult]    = useState<RunResult | null>(null)
  const [loading,   setLoading]   = useState(false)
  const [error,     setError]     = useState('')
  const [showDiff,  setShowDiff]  = useState(false)

  // Load original BOM text when bomPath changes
  useEffect(() => {
    if (!bomPath) { setOrigText(''); return }
    window.sbomBridge.readFile(bomPath)
      .then(setOrigText)
      .catch(() => setOrigText(''))
  }, [bomPath])

  const pickBom = useCallback(async () => {
    const p = await window.sbomBridge.openFile()
    if (p) setBomPath(p)
  }, [])

  const pickPatch = useCallback(async () => {
    const p = await window.sbomBridge.openFile()
    if (p) setPatchPath(p)
  }, [])

  const runPatch = useCallback(async () => {
    if (!bomPath || !patchPath) {
      setError('Please select both a BOM file and a patch file.')
      return
    }
    setError('')
    setLoading(true)
    try {
      const r = await window.sbomBridge.applyPatch({ bomPath, patchPath })
      setResult(r)
    } catch (e: unknown) {
      setError(String(e))
    } finally {
      setLoading(false)
    }
  }, [bomPath, patchPath])

  const outputText = result
    ? (result.stdout || '') + (result.stderr ? '\n' + result.stderr : '')
    : ''

  return (
    <div className={styles.screen}>

      {/* ── Top bar ──────────────────────────────────────────────────────────── */}
      <div className={styles.topBar}>
        <span style={{ fontWeight: 600, fontSize: 13 }}>Apply Patch</span>
        {result && (
          <span style={{
            fontSize: 11,
            color: result.code === 0 ? 'var(--color-success)' : 'var(--color-error)',
            marginLeft: 'auto',
          }}>
            {result.code === 0 ? '✓ Patch applied' : `✗ Patch failed (exit ${result.code})`}
          </span>
        )}
        {result && (
          <button
            className="btn-default"
            style={{ fontSize: 11, marginLeft: 8 }}
            onClick={() => setShowDiff(v => !v)}
          >
            {showDiff ? 'Show Output' : 'Show Diff'}
          </button>
        )}
      </div>

      {/* ── Split ────────────────────────────────────────────────────────────── */}
      <div className={styles.split}>

        {/* Options */}
        <div className={styles.options}>
          <div style={{ padding: 'var(--space-4)', display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>

            <label style={{ fontSize: 12, color: 'var(--color-text-muted)', fontWeight: 600 }}>
              BOM File
            </label>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-1)' }}>
              <span style={{ fontSize: 11, color: 'var(--color-text-muted)', wordBreak: 'break-all', minHeight: 16 }}>
                {bomPath || '—'}
              </span>
              <button className="btn-default" style={{ alignSelf: 'flex-start' }} onClick={pickBom}>
                Browse…
              </button>
            </div>

            <label style={{ fontSize: 12, color: 'var(--color-text-muted)', fontWeight: 600, marginTop: 8 }}>
              Patch File
            </label>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-1)' }}>
              <span style={{ fontSize: 11, color: 'var(--color-text-muted)', wordBreak: 'break-all', minHeight: 16 }}>
                {patchPath || '—'}
              </span>
              <button className="btn-default" style={{ alignSelf: 'flex-start' }} onClick={pickPatch}>
                Browse…
              </button>
            </div>

            {error && (
              <div style={{ fontSize: 11, color: 'var(--color-error)', marginTop: 4 }}>
                {error}
              </div>
            )}

            <button
              className="btn-primary"
              style={{ marginTop: 'var(--space-4)' }}
              disabled={loading || !bomPath || !patchPath}
              onClick={runPatch}
            >
              {loading ? 'Applying…' : 'Apply Patch'}
            </button>

          </div>
        </div>

        {/* Results: before/after stacked vertically */}
        <div className={styles.results} style={{ display: 'flex', flexDirection: 'column' }}>

          {/* Before (original BOM) — always shown */}
          <div style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column', borderBottom: '1px solid var(--viewer-border)' }}>
            <div style={{ padding: '4px 12px', background: '#2a2a2d', fontSize: 11, color: '#8e8e93', flexShrink: 0 }}>
              Original BOM
            </div>
            <JsonEditor text={origText} />
          </div>

          {/* After (patched output) */}
          <div style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
            <div style={{ padding: '4px 12px', background: '#2a2a2d', fontSize: 11, color: '#8e8e93', flexShrink: 0 }}>
              {result ? (showDiff ? 'Diff View' : 'Patched Output') : 'Patched Output'}
            </div>
            {showDiff
              ? <DiffHighlighter text={outputText} loading={loading} />
              : <JsonEditor text={outputText} loading={loading} />
            }
          </div>

        </div>

      </div>
    </div>
  )
}
