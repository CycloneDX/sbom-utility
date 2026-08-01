// SPDX-License-Identifier: Apache-2.0
/**
 * JsonEditor — context-aware JSON viewer with optional editing.
 *
 * Features (all zero-dependency, pure React + CSS):
 *   • Syntax highlighting — keys, strings, numbers, keywords, brackets
 *   • CycloneDX-aware key highlighting + PURL string colouring
 *   • Rainbow bracket colour coding (3 depth levels, cycling)
 *   • Collapsible folding with gutter chevrons
 *   • In-pane Ctrl/Cmd+F search with Next/Prev navigation
 *   • Line numbers in gutter
 *   • Word-wrap toggle
 *   • Editable mode — transparent textarea overlay sits atop the
 *     highlighted view so syntax colours are always visible while editing
 *   • Font / size picker via the "Font…" toolbar button
 *
 * Props:
 *   text        — raw JSON string to display
 *   loading     — show a loading placeholder
 *   onChange    — when supplied, the editor becomes editable; called with the new text
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { tokenize, splitIntoLines }      from './JsonTokenizer'
import JsonHighlighter                   from './JsonHighlighter'
import { buildFoldInfo, toggleFold }     from './FoldingController'
import FontDialog                        from './FontDialog'
import { useAppContext }                 from '../../context/AppContext'
import styles                            from './JsonEditor.module.css'

// ── Types ─────────────────────────────────────────────────────────────────────

interface Props {
  text:       string
  loading?:   boolean
  /** When supplied the editor becomes editable; called on every keystroke */
  onChange?:  (newText: string) => void
}

// ── Search helpers ────────────────────────────────────────────────────────────

function buildMatchLines(lines: ReturnType<typeof splitIntoLines>, query: string): number[] {
  if (!query) return []
  const lower = query.toLowerCase()
  const matches: number[] = []
  for (let i = 0; i < lines.length; i++) {
    const lineText = lines[i].map(t => t.raw).join('').toLowerCase()
    if (lineText.includes(lower)) matches.push(i + 1)  // 1-based
  }
  return matches
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function JsonEditor({ text, loading, onChange }: Props) {
  const scrollRef  = useRef<HTMLDivElement>(null)
  const textareaRef = useRef<HTMLTextAreaElement>(null)

  // ── Font settings from global context ──────────────────────────────────────
  const { editorFont, setEditorFont } = useAppContext()
  const [fontDialogOpen, setFontDialogOpen] = useState(false)

  // ── Word-wrap toggle ────────────────────────────────────────────────────────
  const [wordWrap, setWordWrap] = useState(false)

  // ── Tokenise + line-split (memoised — only reruns when text changes) ────────
  const lines = useMemo(() => {
    if (!text) return []
    return splitIntoLines(tokenize(text))
  }, [text])

  // ── Fold info (memoised — only reruns when lines change) ────────────────────
  const { foldMap, innerLines } = useMemo(() => buildFoldInfo(lines), [lines])

  // ── Fold state ──────────────────────────────────────────────────────────────
  const [foldedLines, setFoldedLines] = useState<Set<number>>(new Set())

  // Reset fold state when file changes
  useEffect(() => { setFoldedLines(new Set()) }, [text])

  const handleFold = useCallback((openLine: number) => {
    setFoldedLines(prev => toggleFold(openLine, prev, innerLines))
  }, [innerLines])

  // ── Collapse All / Expand All ───────────────────────────────────────────────
  const collapseAll = useCallback(() => {
    const next = new Set<number>()
    for (const [openLine] of foldMap) {
      next.add(openLine)
    }
    setFoldedLines(next)
  }, [foldMap])

  const expandAll = useCallback(() => {
    setFoldedLines(new Set())
  }, [])

  // ── Find bar ────────────────────────────────────────────────────────────────
  const [findOpen,    setFindOpen]    = useState(false)
  const [findQuery,   setFindQuery]   = useState('')
  const [findIdx,     setFindIdx]     = useState(0)
  const findInputRef                  = useRef<HTMLInputElement>(null)

  const matchLines = useMemo(
    () => buildMatchLines(lines, findQuery),
    [lines, findQuery]
  )
  const matchSet = useMemo(() => new Set(matchLines), [matchLines])

  const openFind = useCallback(() => {
    setFindOpen(true)
    setTimeout(() => findInputRef.current?.focus(), 0)
  }, [])

  const closeFind = useCallback(() => {
    setFindOpen(false)
    setFindQuery('')
    setFindIdx(0)
  }, [])

  const findNext = useCallback(() => {
    if (!matchLines.length) return
    const next = (findIdx + 1) % matchLines.length
    setFindIdx(next)
    scrollToLine(matchLines[next])
  }, [findIdx, matchLines])

  const findPrev = useCallback(() => {
    if (!matchLines.length) return
    const prev = (findIdx - 1 + matchLines.length) % matchLines.length
    setFindIdx(prev)
    scrollToLine(matchLines[prev])
  }, [findIdx, matchLines])

  // When a new search produces results, jump to first match
  useEffect(() => {
    if (matchLines.length > 0) {
      setFindIdx(0)
      scrollToLine(matchLines[0])
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [findQuery])

  function scrollToLine(lineNum: number) {
    const el = scrollRef.current?.querySelector(`[data-line="${lineNum}"]`) as HTMLElement | null
    el?.scrollIntoView({ block: 'center', behavior: 'smooth' })
  }

  // ── Keyboard shortcuts ──────────────────────────────────────────────────────
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      const mod = e.metaKey || e.ctrlKey
      if (mod && e.key === 'f') {
        e.preventDefault()
        openFind()
      }
      if (e.key === 'Escape' && findOpen) {
        closeFind()
      }
      if (findOpen && e.key === 'Enter') {
        e.preventDefault()
        e.shiftKey ? findPrev() : findNext()
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [findOpen, openFind, closeFind, findNext, findPrev])

  // ── Render ──────────────────────────────────────────────────────────────────

  // Font inline style applied to the .editor root so everything inherits it
  const fontStyle: React.CSSProperties = {
    fontFamily: editorFont.family,
    fontSize:   editorFont.size,
  }

  if (loading) {
    return (
      <div className={styles.editor} style={fontStyle}>
        <div className={styles.placeholder}>Reading file…</div>
      </div>
    )
  }

  if (!text) {
    return (
      <div className={styles.editor} style={fontStyle}>
        <div className={styles.placeholder}>
          No BOM file loaded — click "Load BOM" in the sidebar.
        </div>
      </div>
    )
  }

  return (
    <div className={styles.editor} style={fontStyle}>

      {/* ── Toolbar ─────────────────────────────────────────────────────────── */}
      <div className={styles.toolbar}>
        <button
          className={`${styles.toolbarBtn}${wordWrap ? ' ' + styles.active : ''}`}
          onClick={() => setWordWrap(v => !v)}
          title="Toggle word wrap"
        >
          Wrap
        </button>
        <div className={styles.toolbarSep} />
        <button
          className={styles.toolbarBtn}
          onClick={collapseAll}
          title="Collapse all foldable regions"
        >
          Collapse All
        </button>
        <button
          className={styles.toolbarBtn}
          onClick={expandAll}
          title="Expand all foldable regions"
        >
          Expand All
        </button>
        <div className={styles.toolbarSep} />
        <button
          className={styles.toolbarBtn}
          onClick={openFind}
          title="Find (Ctrl/Cmd+F)"
        >
          Find
        </button>
        <div className={styles.toolbarSep} />
        <button
          className={styles.toolbarBtn}
          onClick={() => setFontDialogOpen(true)}
          title="Change editor font and size"
        >
          Font…
        </button>
        <div className={styles.toolbarSpacer} />
        <span style={{ fontSize: 11, color: '#5a5a5e' }}>
          {lines.length} lines
        </span>
      </div>

      {/* ── Find bar ────────────────────────────────────────────────────────── */}
      {findOpen && (
        <div className={styles.findBar}>
          <input
            ref={findInputRef}
            className={styles.findInput}
            type="text"
            placeholder="Find…"
            value={findQuery}
            onChange={e => setFindQuery(e.target.value)}
            spellCheck={false}
          />
          <span className={styles.findCount}>
            {matchLines.length > 0
              ? `${findIdx + 1} / ${matchLines.length}`
              : findQuery ? '0 results' : ''}
          </span>
          <button className={styles.findBtn} onClick={findPrev} title="Previous match (Shift+Enter)">
            ↑
          </button>
          <button className={styles.findBtn} onClick={findNext} title="Next match (Enter)">
            ↓
          </button>
          <button className={`${styles.findBtn} ${styles.findClose}`} onClick={closeFind} title="Close (Esc)">
            ×
          </button>
        </div>
      )}

      {/* ── Scrollable code body ─────────────────────────────────────────────── */}
      <div
        className={styles.scroll}
        ref={scrollRef}
      >
        {/*
          The highlighted view is ALWAYS rendered (provides syntax colours).
          When onChange is supplied, a transparent textarea overlays it to
          capture keystrokes — the classic code-editor trick.
        */}
        <div
          className={`${styles.codePane}${wordWrap ? ' ' + styles.wrap : ''}`}
          style={{ paddingBottom: 'var(--space-8)' }}
        >
          <JsonHighlighter
            lines={lines}
            foldMap={foldMap}
            foldedLines={foldedLines}
            onFold={handleFold}
            matchLines={matchSet}
            showGutter
          />
          {onChange && (
            <textarea
              ref={textareaRef}
              className={styles.editableOverlay}
              value={text}
              onChange={e => onChange(e.target.value)}
              spellCheck={false}
              autoCapitalize="off"
              autoCorrect="off"
              aria-label="JSON editor"
            />
          )}
        </div>
      </div>

      {/* ── Font dialog (portal-style overlay) ──────────────────────────────── */}
      {fontDialogOpen && (
        <FontDialog
          current={editorFont}
          onApply={font => { setEditorFont(font); setFontDialogOpen(false) }}
          onCancel={() => setFontDialogOpen(false)}
        />
      )}

    </div>
  )
}
