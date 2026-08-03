// SPDX-License-Identifier: Apache-2.0
import { useCallback, useEffect, useRef, useState } from 'react'
import { useAppContext } from '../../context/AppContext'
import type { ValidateBadge } from '../../context/AppContext'
import OptionsPanel from '../OptionsPanel'
import ResultsView  from '../ResultsView'
import JsonEditor   from '../editor/JsonEditor'
import styles from './Screen.module.css'

const DEFAULT_MAX_ERRORS = 10

interface Props { active: boolean }

export default function ValidateScreen({ active }: Props) {
  const {
    bomFile, bomDisplayName, setDirty: setGlobalDirty,
    validateBadge, validateBadgeText, setValidateBadge,
    autoValidateOnLoad,
  } = useAppContext()

  // ── File content & dirty tracking (from former ViewScreen) ────────────────
  const [savedText,  setSavedText]  = useState('')
  const [editedText, setEditedText] = useState('')
  const [fileLoading, setFileLoading] = useState(false)
  const [saveError,  setSaveError]  = useState('')
  const loadedPath = useRef('')

  const isDirty = editedText !== savedText && savedText !== ''
  useEffect(() => { setGlobalDirty(isDirty) }, [isDirty, setGlobalDirty])

  useEffect(() => {
    if (!bomFile) {
      setSavedText(''); setEditedText(''); loadedPath.current = ''; return
    }
    setFileLoading(true)
    setSaveError('')
    window.sbomBridge.readFile(bomFile)
      .then((t: string) => {
        setSavedText(t); setEditedText(t)
        loadedPath.current = bomFile
        setFileLoading(false)
      })
      .catch((e: Error) => {
        const msg = `[ERROR] ${e?.message ?? String(e)}`
        setSavedText(msg); setEditedText(msg)
        setFileLoading(false)
      })
  }, [bomFile])

  // ── Save As ───────────────────────────────────────────────────────────────
  const [confirmOverwrite, setConfirmOverwrite] = useState(false)
  const pendingPath = useRef('')

  async function handleSaveAs() {
    setSaveError('')
    const chosen = await window.sbomBridge.saveFileDialog(loadedPath.current)
    if (!chosen) return
    if (chosen === loadedPath.current) {
      pendingPath.current = chosen; setConfirmOverwrite(true)
    } else {
      await doWrite(chosen)
    }
  }

  async function doWrite(targetPath: string) {
    try {
      await window.sbomBridge.writeFile(targetPath, editedText)
      setSavedText(editedText)
      loadedPath.current = targetPath
    } catch (e: unknown) {
      setSaveError(`Save failed: ${e instanceof Error ? e.message : String(e)}`)
    }
  }

  // ── Results pane: resize + collapse ──────────────────────────────────────
  const PANE_DEFAULT = 220
  const PANE_MIN     = 80
  const [paneHeight,   setPaneHeight]   = useState(PANE_DEFAULT)
  const [paneOpen,     setPaneOpen]     = useState(true)
  const heightBeforeCollapse = useRef(PANE_DEFAULT)

  const startResize = useCallback((e: React.PointerEvent<HTMLDivElement>) => {
    e.preventDefault()
    const startY    = e.clientY
    const startH    = paneHeight

    const onMove = (ev: PointerEvent) => {
      // dragging UP increases pane height (delta is negative → pane grows)
      const next = Math.max(PANE_MIN, startH - (ev.clientY - startY))
      setPaneHeight(next)
    }
    const onUp = () => {
      window.removeEventListener('pointermove', onMove)
      window.removeEventListener('pointerup',   onUp)
    }
    window.addEventListener('pointermove', onMove)
    window.addEventListener('pointerup',   onUp)
  }, [paneHeight])

  function toggleCollapse() {
    if (paneOpen) {
      heightBeforeCollapse.current = paneHeight
      setPaneOpen(false)
    } else {
      setPaneHeight(heightBeforeCollapse.current)
      setPaneOpen(true)
    }
  }

  // ── Validate ──────────────────────────────────────────────────────────────
  const [output,     setOutput]     = useState('')
  const [loading,    setLoading]    = useState(false)
  const [dirty,      setDirty]      = useState(true)
  const [noticeMsg,  setNoticeMsg]  = useState('')

  const [variant,    setVariant]    = useState('')
  const [force,      setForce]      = useState('')
  const [maxErrors,  setMaxErrors]  = useState(String(DEFAULT_MAX_ERRORS))
  const [showValues, setShowValues] = useState(true)

  const markDirty = () => { setDirty(true); setNoticeMsg('') }

  // Reset dirty when the loaded file changes so the first run always proceeds.
  useEffect(() => { setDirty(true); setNoticeMsg('') }, [bomFile])

  const run = useCallback(async () => {
    if (!bomFile) return
    if (!dirty) { setNoticeMsg('No option changes — results are current'); return }
    setLoading(true)
    setOutput('')
    setValidateBadge('idle', '')
    try {
      const res = await window.sbomBridge.validate({
        filePath:    bomFile,
        variant:     variant || undefined,
        forceSchema: force   || undefined,
        maxErrors:   parseInt(maxErrors, 10) || DEFAULT_MAX_ERRORS,
        showValues,
      })
      console.debug('[validate] res.code:', res.code, 'stdout len:', res.stdout.length, 'stderr len:', res.stderr.length)
      const combined = res.stdout + (res.stderr ? '\n' + res.stderr : '')
      if (res.code === 0) {
        setOutput(combined || 'BOM document is VALID — no schema errors found.')
        setValidateBadge('valid', 'VALID')
      } else {
        setOutput(combined || '[Validation failed — no output captured]')
        setValidateBadge('invalid', 'INVALID')
      }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e)
      setOutput(`[ERROR] ${msg}`)
      setValidateBadge('invalid', 'ERROR')
    } finally {
      setDirty(false)
      setLoading(false)
    }
  }, [bomFile, dirty, variant, force, maxErrors, showValues, setValidateBadge])

  // Auto-run whenever the active file changes (if preference is on).
  useEffect(() => { if (active && bomFile && autoValidateOnLoad) { run() } }, [active, bomFile, autoValidateOnLoad, run])

  // ── Render ────────────────────────────────────────────────────────────────
  const badge     = validateBadge
  const badgeText = validateBadgeText

  return (
    <div className={styles.screen}>

      {/* ── Main split: options | editor+results ─── */}
      <div className={styles.split}>

        {/* Options column */}
        <div className={styles.options}>
          <OptionsPanel
            title="Validate Options"
            notice={noticeMsg}
            action={
              <button className="btn btn-primary w-full" onClick={run} disabled={loading || !bomFile}>
                ✅ &nbsp;{loading ? 'Validating…' : 'Validate'}
              </button>
            }
          >
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
          </OptionsPanel>
        </div>

        {/* Right column: top bar + JSON editor + (optional) results pane */}
        <div className={styles.editorColumn}>

          {/* Top bar: path + Save As — scoped to editor column only */}
          <div className={styles.topBar}>
            <span className={styles.pathLabelInline}>
              {bomFile ? `Loaded: ${bomDisplayName}` : 'No file loaded — click "Load BOM" in the sidebar.'}
            </span>

            <div className={styles.topBarSpacer} />

            {bomFile && (
              <button
                className={`${styles.saveAsBtn}${isDirty ? '' : ' ' + styles.saveAsBtnDisabled}`}
                disabled={!isDirty}
                onClick={handleSaveAs}
                title={isDirty ? 'Save edited file to a new location' : 'No unsaved edits'}
              >
                Save As…
              </button>
            )}
          </div>

          {/* Overwrite confirmation banner */}
          {confirmOverwrite && (
            <div className={styles.overwriteWarning}>
              <span className={styles.overwriteWarningText}>
                ⚠ The chosen filename is the same as the loaded file. Overwrite?
              </span>
              <button className={styles.overwriteConfirmBtn} onClick={() => { setConfirmOverwrite(false); doWrite(pendingPath.current) }}>
                Overwrite
              </button>
              <button className={styles.overwriteCancelBtn} onClick={() => { setConfirmOverwrite(false); pendingPath.current = '' }}>
                Cancel
              </button>
            </div>
          )}

          {/* Save error notice */}
          {saveError && <div className={styles.saveErrorBanner}>{saveError}</div>}

          <JsonEditor
            text={editedText}
            loading={fileLoading}
            onChange={bomFile ? setEditedText : undefined}
          />

          {/* Validate results — only shown after a run */}
          {(output || loading) && (
            <div
              className={styles.resultsPane}
              style={{ height: paneOpen ? paneHeight : undefined, flex: paneOpen ? '0 0 auto' : '0 0 auto' }}
            >
              {/* Drag-to-resize handle */}
              {paneOpen && (
                <div
                  className={styles.resultsPaneResizeHandle}
                  onPointerDown={startResize}
                  title="Drag to resize"
                />
              )}

              <div className={styles.resultsPaneHeader}>
                <span className={`badge badge-${badge as ValidateBadge}`} style={{ fontSize: 10 }}>
                  <span className="badge-dot" />
                  {badge === 'idle' ? 'Running…' : badgeText}
                </span>
                <span className={styles.resultsPaneTitle}>Validation output</span>
                <button
                  className={styles.resultsPaneCollapseBtn}
                  onClick={toggleCollapse}
                  title={paneOpen ? 'Collapse validation output' : 'Expand validation output'}
                >
                  {paneOpen ? '▼' : '▲'}
                </button>
              </div>

              {paneOpen && <ResultsView text={output} loading={loading} />}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
