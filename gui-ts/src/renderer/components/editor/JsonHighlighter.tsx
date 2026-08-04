// SPDX-License-Identifier: Apache-2.0
/**
 * JsonHighlighter — renders an array of TokenLines as colour-coded spans.
 *
 * Each line becomes a <div class="jl"> (json-line).
 * Each token becomes a <span> with one or more class names derived from its
 * type and flags.  Bracket spans also carry a data-depth attribute so CSS
 * can apply rainbow colour cycling.
 *
 * The component is memoised: it only re-renders when the tokens prop changes.
 */
import { memo } from 'react'
import type { Token, TokenLine } from './JsonTokenizer'
import styles from './JsonEditor.module.css'

// ── Token → CSS class ─────────────────────────────────────────────────────────

function tokenClass(tok: Token): string {
  switch (tok.type) {
    case 'key':
      return tok.cdxKey
        ? `${styles.tokKey} ${styles.tokCdxKey}`
        : styles.tokKey
    case 'string':
      return tok.isPurl
        ? `${styles.tokString} ${styles.tokPurl}`
        : styles.tokString
    case 'number':
      return styles.tokNumber
    case 'keyword':
      return styles.tokKeyword
    case 'bracket': {
      const d = (tok.depth ?? 0) % 3
      return `${styles.tokBracket} ${styles[`tokBracket${d}` as keyof typeof styles] ?? ''}`
    }
    case 'punctuation':
      return styles.tokPunct
    default:
      return ''
  }
}

// ── Line renderer ─────────────────────────────────────────────────────────────

interface LineProps {
  lineNumber: number
  tokens:     Token[]
  isFolded?:  boolean
  foldCount?: number   // number of lines hidden by this fold
  onFold?:    (line: number) => void
  isMatch?:   boolean  // true when this line contains a search match
  showGutter: boolean
}

export function JsonLine({
  lineNumber, tokens, isFolded, foldCount, onFold, isMatch, showGutter
}: LineProps) {
  const hasFold = foldCount !== undefined && foldCount > 0

  return (
    <div
      className={`${styles.line}${isMatch ? ' ' + styles.lineMatch : ''}`}
      data-line={lineNumber}
    >
      {showGutter && (
        <span className={styles.gutter} aria-hidden>
          {hasFold && (
            <button
              className={styles.foldBtn}
              onClick={() => onFold?.(lineNumber)}
              tabIndex={-1}
              aria-label={isFolded ? 'Expand' : 'Collapse'}
            >
              {isFolded ? '▶' : '▼'}
            </button>
          )}
          {!hasFold && <span className={styles.gutterNum}>{lineNumber}</span>}
        </span>
      )}
      <span className={styles.lineContent}>
        {isFolded ? (
          <span className={styles.foldPlaceholder}>
            {tokens.map(t => t.raw).join('')}
            <span className={styles.foldEllipsis}> … {foldCount} lines </span>
          </span>
        ) : (
          tokens.map((tok, i) => {
            const cls = tokenClass(tok)
            if (tok.type === 'bracket') {
              return (
                <span
                  key={i}
                  className={cls}
                  data-depth={tok.depth ?? 0}
                >
                  {tok.raw}
                </span>
              )
            }
            if (!cls) return <span key={i}>{tok.raw}</span>
            return <span key={i} className={cls}>{tok.raw}</span>
          })
        )}
      </span>
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

interface Props {
  lines:       TokenLine[]
  foldMap?:    Map<number, number>   // lineNumber (1-based) → count of hidden lines
  foldedLines?: Set<number>          // 1-based line numbers currently folded
  onFold?:     (line: number) => void
  matchLines?: Set<number>           // 1-based line numbers with a search match
  showGutter?: boolean
  startLine?:  number                // first visible line index offset (for virtual scroll)
}

const JsonHighlighter = memo(function JsonHighlighter({
  lines,
  foldMap,
  foldedLines,
  onFold,
  matchLines,
  showGutter = true,
  startLine  = 0,
}: Props) {
  const rendered: JSX.Element[] = []
  let i = 0
  while (i < lines.length) {
    const lineNumber = startLine + i + 1  // 1-based
    const isFolded   = foldedLines?.has(lineNumber) ?? false
    const foldCount  = foldMap?.get(lineNumber)

    rendered.push(
      <JsonLine
        key={lineNumber}
        lineNumber={lineNumber}
        tokens={lines[i]}
        isFolded={isFolded}
        foldCount={foldCount}
        onFold={onFold}
        isMatch={matchLines?.has(lineNumber)}
        showGutter={showGutter}
      />
    )

    // If this line is folded, skip the hidden lines
    if (isFolded && foldCount && foldCount > 0) {
      i += foldCount + 1
    } else {
      i++
    }
  }

  return <>{rendered}</>
})

export default JsonHighlighter
