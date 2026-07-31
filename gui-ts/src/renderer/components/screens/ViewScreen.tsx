// SPDX-License-Identifier: Apache-2.0
import { useEffect, useRef, useState } from 'react'
import { useAppContext } from '../../context/AppContext'
import JsonEditor from '../editor/JsonEditor'
import styles from './Screen.module.css'

export default function ViewScreen() {
  const { bomFile } = useAppContext()

  // ── File content & dirty tracking ─────────────────────────────────────────
  const [savedText,  setSavedText]  = useState('')   // last-saved / loaded version
  const [editedText, setEditedText] = useState('')   // live in-editor text
  const [loading,    setLoading]    = useState(false)
  const [saveError,  setSaveError]  = useState('')

  // Track the original loaded path so we can detect same-file overwrites
  const loadedPath = useRef('')

  const isDirty = editedText !== savedText && savedText !== ''

  // Re-load whenever the user picks a new BOM file
  useEffect(() => {
    if (!bomFile) {
      setSavedText('')
      setEditedText('')
      loadedPath.current = ''
      return
    }
    setLoading(true)
    setSaveError('')
    window.sbomBridge.readFile(bomFile)
      .then((t: string) => {
        setSavedText(t)
        setEditedText(t)
        loadedPath.current = bomFile
        setLoading(false)
      })
      .catch((e: Error) => {
        const msg = `[ERROR] ${e?.message ?? String(e)}`
        setSavedText(msg)
        setEditedText(msg)
        setLoading(false)
      })
  }, [bomFile])

  // ── Save As ───────────────────────────────────────────────────────────────
  const [confirmOverwrite, setConfirmOverwrite] = useState(false)
  const pendingPath = useRef('')

  async function handleSaveAs() {
    setSaveError('')
    const chosen = await window.sbomBridge.saveFileDialog(loadedPath.current)
    if (!chosen) return   // user cancelled

    // If the chosen path is the same as the loaded file, ask for confirmation
    if (chosen === loadedPath.current) {
      pendingPath.current = chosen
      setConfirmOverwrite(true)
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
      const msg = e instanceof Error ? e.message : String(e)
      setSaveError(`Save failed: ${msg}`)
    }
  }

  function handleConfirmOverwrite() {
    setConfirmOverwrite(false)
    doWrite(pendingPath.current)
  }

  function handleCancelOverwrite() {
    setConfirmOverwrite(false)
    pendingPath.current = ''
  }

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <div className={styles.screen}>

      {/* Top bar — path label + Save As button */}
      <div className={styles.topBar}>
        <span className={styles.pathLabelInline}>
          {bomFile ? `Loaded: ${bomFile}` : 'No file loaded — click "Load BOM" in the sidebar.'}
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
          <button className={styles.overwriteConfirmBtn} onClick={handleConfirmOverwrite}>
            Overwrite
          </button>
          <button className={styles.overwriteCancelBtn} onClick={handleCancelOverwrite}>
            Cancel
          </button>
        </div>
      )}

      {/* Save error notice */}
      {saveError && (
        <div className={styles.saveErrorBanner}>
          {saveError}
        </div>
      )}

      <JsonEditor
        text={editedText}
        loading={loading}
        onChange={bomFile ? setEditedText : undefined}
      />
    </div>
  )
}
