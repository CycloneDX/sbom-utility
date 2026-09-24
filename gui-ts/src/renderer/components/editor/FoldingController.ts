// SPDX-License-Identifier: Apache-2.0
/**
 * FoldingController — builds fold metadata from bracket pairs.
 *
 * Returns two data structures:
 *   foldMap    — Map<openLine, hiddenLineCount>
 *                The gutter renders a fold chevron on each key in this map.
 *   nestedMap  — Map<openLine, Set<hiddenLines>>
 *                Used to skip lines when rendering while folded.
 */
import type { TokenLine } from './JsonTokenizer'
import { buildBracketPairs } from './BracketMatcher'

export interface FoldInfo {
  /** openLine (1-based) → number of lines hidden when folded */
  foldMap:    Map<number, number>
  /** openLine (1-based) → sorted array of 1-based line numbers inside the fold */
  innerLines: Map<number, number[]>
}

export function buildFoldInfo(lines: TokenLine[]): FoldInfo {
  const pairs = buildBracketPairs(lines)
  const foldMap    = new Map<number, number>()
  const innerLines = new Map<number, number[]>()

  for (const pair of pairs) {
    const count = pair.closeLine - pair.openLine - 1
    if (count <= 0) continue  // nothing to fold

    foldMap.set(pair.openLine, count)

    const inner: number[] = []
    for (let l = pair.openLine + 1; l < pair.closeLine; l++) inner.push(l)
    innerLines.set(pair.openLine, inner)
  }

  return { foldMap, innerLines }
}

/**
 * Toggle a fold: returns the new foldedLines set.
 * If the fold is currently open, adds all inner lines to foldedLines.
 * If the fold is currently closed, removes all inner lines.
 */
export function toggleFold(
  openLine:   number,
  foldedLines: Set<number>,
  innerLines:  Map<number, number[]>,
): Set<number> {
  const next = new Set(foldedLines)
  const inner = innerLines.get(openLine) ?? []

  if (foldedLines.has(openLine)) {
    // Currently folded → expand
    next.delete(openLine)
    for (const l of inner) next.delete(l)
  } else {
    // Currently expanded → fold: mark the open line as the fold anchor
    // and hide all inner lines.
    next.add(openLine)
    // Also recursively collapse any nested folds back to their open state
    for (const l of inner) next.delete(l)
  }

  return next
}
