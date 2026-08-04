// SPDX-License-Identifier: Apache-2.0
/**
 * BracketMatcher — assigns a cycling depth class (0/1/2) to each bracket token.
 *
 * This is already handled inside JsonTokenizer (the `depth` field), but this
 * module provides utilities for:
 *   - Building a bracket-pair map (open-line → close-line) for fold support
 *   - Matching the partner of a bracket at a given token index
 */
import type { TokenLine } from './JsonTokenizer'

export interface BracketPair {
  openLine:  number   // 1-based
  closeLine: number   // 1-based
  depth:     number
}

/**
 * Walk all lines and return every matched bracket pair.
 * Used by FoldingController to know which regions are foldable.
 */
export function buildBracketPairs(lines: TokenLine[]): BracketPair[] {
  // stack entries: { lineNum (1-based), depth }
  const stack: Array<{ lineNum: number; depth: number }> = []
  const pairs: BracketPair[] = []

  for (let i = 0; i < lines.length; i++) {
    const lineNum = i + 1
    for (const tok of lines[i]) {
      if (tok.type !== 'bracket') continue
      if (tok.raw === '{' || tok.raw === '[') {
        stack.push({ lineNum, depth: tok.depth ?? 0 })
      } else {
        const open = stack.pop()
        if (open && open.lineNum !== lineNum) {
          // Only record pairs that span at least one line (foldable)
          pairs.push({ openLine: open.lineNum, closeLine: lineNum, depth: open.depth })
        }
      }
    }
  }

  return pairs
}
