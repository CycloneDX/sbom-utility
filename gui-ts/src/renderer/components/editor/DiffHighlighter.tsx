// SPDX-License-Identifier: Apache-2.0
/**
 * DiffHighlighter — renders a unified-diff text block with line-level colour coding.
 *
 * Handles the plain-text output produced by:
 *   sbom-utility diff --format text
 *
 * Line classification:
 *   '+'  prefix → added   (green background)
 *   '-'  prefix → removed (red background)
 *   '@@' prefix → hunk header (comment green, italic)
 *   '---'/'+++' prefix → file header (muted)
 *   everything else → context (default fg)
 *
 * The component is purely presentational — no state, no side-effects.
 */
import styles from './JsonEditor.module.css'

// ── Types ─────────────────────────────────────────────────────────────────────

type DiffLineType = 'added' | 'removed' | 'header' | 'fileheader' | 'context'

interface DiffLine {
  type:   DiffLineType
  text:   string
  num:    number
}

// ── Classifier ────────────────────────────────────────────────────────────────

function classifyLine(text: string): DiffLineType {
  if (text.startsWith('+++') || text.startsWith('---')) return 'fileheader'
  if (text.startsWith('@@'))                              return 'header'
  if (text.startsWith('+'))                              return 'added'
  if (text.startsWith('-'))                              return 'removed'
  return 'context'
}

function parseLines(raw: string): DiffLine[] {
  return raw.split('\n').map((text, i) => ({
    type: classifyLine(text),
    text,
    num:  i + 1,
  }))
}

// ── CSS class for line type ───────────────────────────────────────────────────

function lineClass(type: DiffLineType): string {
  switch (type) {
    case 'added':      return styles.diffAdded
    case 'removed':    return styles.diffRemoved
    case 'header':     return styles.diffHeader
    case 'fileheader': return styles.diffHeader
    default:           return styles.diffContext
  }
}

// ── Component ─────────────────────────────────────────────────────────────────

interface Props {
  text:       string
  loading?:   boolean
  showGutter?: boolean
}

export default function DiffHighlighter({ text, loading, showGutter = true }: Props) {
  if (loading) {
    return (
      <div className={styles.editor}>
        <div className={styles.placeholder}>Running diff…</div>
      </div>
    )
  }

  if (!text) {
    return (
      <div className={styles.editor}>
        <div className={styles.placeholder}>Diff output will appear here.</div>
      </div>
    )
  }

  const lines = parseLines(text)

  return (
    <div className={styles.editor}>
      <div className={styles.scroll}>
        <div style={{ paddingBottom: 'var(--space-8)' }}>
          {lines.map(line => (
            <div
              key={line.num}
              className={`${styles.line} ${lineClass(line.type)}`}
              data-line={line.num}
            >
              {showGutter && (
                <span className={styles.gutter} aria-hidden>
                  <span className={styles.gutterNum}>{line.num}</span>
                </span>
              )}
              <span className={styles.lineContent} style={{ whiteSpace: 'pre' }}>
                {line.text || ' '}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
