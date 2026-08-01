// SPDX-License-Identifier: Apache-2.0
/**
 * DiffScreen — compare two CycloneDX BOM files using `sbom-utility diff`.
 *
 * Layout: options panel (left) | diff output (right)
 * The right pane uses DiffHighlighter to colour-code added/removed/context lines.
 */
import { useState, useEffect, useCallback } from 'react'
import { useAppContext } from '../../context/AppContext'
import DiffHighlighter from '../editor/DiffHighlighter'
import styles from './Screen.module.css'
import type { RunResult } from '../../../preload/index'

interface Props {
  active: boolean
}

export default function DiffScreen({ active }: Props) {
  const { bomFile } = useAppContext()

  const [fileA, setFileA] = useState(bomFile)

  // When the screen becomes active and a BOM is already loaded, default fileA to it.
  useEffect(() => {
    if (active && bomFile) setFileA(bomFile)
  }, [active, bomFile])
  const [fileB, setFileB] = useState('')
  const [result, setResult] = useState<RunResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const pickFileA = useCallback(async () => {
    const p = await window.sbomBridge.openFile()
    if (p) setFileA(p)
  }, [])

  const pickFileB = useCallback(async () => {
    const p = await window.sbomBridge.openFile()
    if (p) setFileB(p)
  }, [])

  const runDiff = useCallback(async () => {
    if (!fileA || !fileB) {
      setError('Please select both BOM files before running diff.')
      return
    }
    setError('')
    setLoading(true)
    try {
      const r = await window.sbomBridge.diffBoms({ fileA, fileB })
      setResult(r)
    } catch (e: unknown) {
      setError(String(e))
    } finally {
      setLoading(false)
    }
  }, [fileA, fileB])

  // Combine stdout + stderr for display; diff output arrives on stdout
  const outputText = result
    ? (result.stdout || '') + (result.stderr ? '\n' + result.stderr : '')
    : ''

  return (
    <div className={styles.screen}>

      {/* ── Top bar ──────────────────────────────────────────────────────────── */}
      <div className={styles.topBar}>
        <span style={{ fontWeight: 600, fontSize: 13 }}>Diff BOM Files</span>
        {result && (
          <span style={{
            fontSize: 11,
            color: result.code === 0 ? 'var(--color-success)' : 'var(--color-warning)',
            marginLeft: 'auto',
          }}>
            {result.code === 0 ? '✓ No differences' : `⚠ Differences found (exit ${result.code})`}
          </span>
        )}
      </div>

      {/* ── Split ────────────────────────────────────────────────────────────── */}
      <div className={styles.split}>

        {/* Options */}
        <div className={styles.options}>
          <div style={{ padding: 'var(--space-4)', display: 'flex', flexDirection: 'column', gap: 'var(--space-3)' }}>

            <label style={{ fontSize: 12, color: 'var(--color-text-muted)', fontWeight: 600 }}>
              BOM File A (base)
            </label>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-1)' }}>
              <span style={{
                fontSize: 11, color: 'var(--color-text-muted)', wordBreak: 'break-all',
                minHeight: 16,
              }}>
                {fileA || '—'}
              </span>
              <button className="btn btn-secondary" style={{ alignSelf: 'flex-start' }} onClick={pickFileA}>
                Browse…
              </button>
            </div>

            <label style={{ fontSize: 12, color: 'var(--color-text-muted)', fontWeight: 600, marginTop: 8 }}>
              BOM File B (revised)
            </label>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-1)' }}>
              <span style={{
                fontSize: 11, color: 'var(--color-text-muted)', wordBreak: 'break-all',
                minHeight: 16,
              }}>
                {fileB || '—'}
              </span>
              <button className="btn btn-secondary" style={{ alignSelf: 'flex-start' }} onClick={pickFileB}>
                Browse…
              </button>
            </div>

            {error && (
              <div style={{ fontSize: 11, color: 'var(--color-error)', marginTop: 4 }}>
                {error}
              </div>
            )}

            <button
              className="btn btn-primary w-full"
              style={{ marginTop: 'var(--space-4)' }}
              disabled={loading || !fileA || !fileB}
              onClick={runDiff}
            >
              {loading ? 'Running…' : 'Run Diff'}
            </button>

          </div>
        </div>

        {/* Results */}
        <div className={styles.results}>
          <DiffHighlighter
            text={outputText}
            loading={loading}
          />
        </div>

      </div>
    </div>
  )
}
