// SPDX-License-Identifier: Apache-2.0
/**
 * ResultsView — shared scrollable output area used by every command screen.
 *
 * Props:
 *   text       — raw text/markdown to display
 *   loading    — show a spinner/placeholder while a command runs
 *   markdown   — if true, renders GitHub-Flavored Markdown pipe tables as <table>
 */
import { useMemo } from 'react'
import styles from './ResultsView.module.css'

interface Props {
  text:     string
  loading?: boolean
  markdown?: boolean
}

// ── Minimal GFM pipe-table parser (mirrors Fyne widgets/results.go) ──────────

interface Segment {
  type: 'text' | 'table'
  text?: string
  rows?: string[][]
}

function isTableLine(line: string): boolean {
  return line.trimStart().startsWith('|')
}

function isSepRow(cells: string[]): boolean {
  return cells.every(c => /^[\s:|-]+$/.test(c))
}

function splitRow(line: string): string[] {
  const trimmed = line.trim().replace(/^\||\|$/g, '')
  return trimmed.split('|').map(c => c.trim())
}

function parseSegments(md: string): Segment[] {
  const lines   = md.split('\n')
  const segs: Segment[] = []
  let textLines: string[] = []

  const flushText = () => {
    // trim trailing blank lines
    while (textLines.length > 0 && textLines[textLines.length - 1].trim() === '') {
      textLines.pop()
    }
    if (textLines.length > 0) segs.push({ type: 'text', text: textLines.join('\n') })
    textLines = []
  }

  let i = 0
  while (i < lines.length) {
    if (isTableLine(lines[i])) {
      // Collect consecutive table lines
      let j = i
      const tblLines: string[] = []
      while (j < lines.length && (isTableLine(lines[j]) || lines[j].trim() === '')) {
        if (isTableLine(lines[j])) tblLines.push(lines[j])
        j++
      }
      const hasSep = tblLines.some(l => isSepRow(splitRow(l)))
      if (hasSep) {
        flushText()
        const rows = tblLines
          .map(l => splitRow(l))
          .filter(cells => !isSepRow(cells))
        if (rows.length > 0) segs.push({ type: 'table', rows })
        i = j
      } else {
        textLines.push(lines[i])
        i++
      }
    } else {
      textLines.push(lines[i])
      i++
    }
  }
  flushText()
  return segs
}

// ── Sub-components ────────────────────────────────────────────────────────────

function MarkdownTable({ rows }: { rows: string[][] }) {
  if (rows.length === 0) return null
  const [header, ...body] = rows
  return (
    <div className={styles.tableWrap}>
      <table className="results-table">
        <thead>
          <tr>{header.map((h, i) => <th key={i}>{h}</th>)}</tr>
        </thead>
        <tbody>
          {body.map((row, ri) => (
            <tr key={ri}>{row.map((cell, ci) => <td key={ci}>{cell}</td>)}</tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function MarkdownView({ text }: { text: string }) {
  const segments = useMemo(() => parseSegments(text), [text])
  return (
    <div className={`${styles.mdView} selectable`}>
      {segments.map((seg, i) =>
        seg.type === 'table'
          ? <MarkdownTable key={i} rows={seg.rows!} />
          : <pre key={i} className={styles.mdPre}>{seg.text}</pre>
      )}
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

export default function ResultsView({ text, loading, markdown }: Props) {
  return (
    <div className={styles.pane}>
      {loading ? (
        <div className={styles.loading}>
          <span className={styles.spinner} aria-hidden />
          Running…
        </div>
      ) : text === '' ? (
        <pre className={`${styles.placeholder} selectable`}>
          Results will appear here…
        </pre>
      ) : markdown ? (
        <MarkdownView text={text} />
      ) : (
        <pre className={`${styles.pre} selectable`}>{text}</pre>
      )}
    </div>
  )
}
