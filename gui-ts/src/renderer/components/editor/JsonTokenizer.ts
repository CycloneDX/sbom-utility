// SPDX-License-Identifier: Apache-2.0
/**
 * JsonTokenizer — single-pass regex lexer for JSON.
 *
 * Produces an array of Token objects from a raw JSON string.
 * Tokens carry a type and, for brackets, a nesting depth so the
 * caller can apply rainbow-bracket colour classes.
 *
 * CycloneDX-aware: keys whose names appear in CDX_KEYWORDS receive the
 * additional 'cdx-key' flag; PURL-valued strings receive 'purl'.
 */

// ── CycloneDX keyword registry ────────────────────────────────────────────────
// Top-level and commonly nested field names from the v1.7 JSON schema.
// Keep sorted for readability; update as the spec evolves.
export const CDX_KEYWORDS = new Set([
  'affects', 'algorithms', 'analysis', 'annotations', 'assemblies',
  'bomFormat', 'bom-ref',
  'certificates', 'cipherSuites', 'commits', 'components', 'compositions',
  'createdUsing', 'cryptoProperties',
  'dataClassification', 'datasets', 'declarations', 'dependencies',
  'description', 'externalReferences',
  'findings', 'formulation',
  'hashes',
  'id', 'identities',
  'licenses', 'lifecycles',
  'manufactures', 'metadata', 'modelCard',
  'name',
  'oid',
  'padding', 'parameterSetIdentifier', 'patches', 'primitiveSize', 'properties', 'publisher', 'purl',
  'rating', 'relatedCryptoMaterialProperties',
  'serialNumber', 'services', 'severity', 'source', 'specVersion', 'supplier',
  'tags', 'tools', 'type',
  'version', 'vulnerabilities',
])

// ── Token types ───────────────────────────────────────────────────────────────

export type TokenType =
  | 'key'           // object key string (without quotes for colouring)
  | 'string'        // non-key string value
  | 'number'        // numeric literal
  | 'keyword'       // true | false | null
  | 'bracket'       // { } [ ]
  | 'punctuation'   // : ,
  | 'whitespace'    // spaces, newlines, tabs

export interface Token {
  type:    TokenType
  raw:     string   // exact source text including surrounding quotes/whitespace
  value:   string   // semantic content (key name, string content, …)
  depth?:  number   // bracket nesting depth (brackets only)
  cdxKey?: boolean  // true when type==='key' and name is in CDX_KEYWORDS
  isPurl?: boolean  // true when type==='string' and value starts with 'pkg:'
}

// ── Lexer ─────────────────────────────────────────────────────────────────────

// Regex fragments (order matters — more-specific before less-specific)
const TOKEN_RE = new RegExp(
  [
    // strings (may contain escaped chars)
    '("(?:[^"\\\\]|\\\\.)*")',
    // numbers
    '(-?(?:0|[1-9]\\d*)(?:\\.\\d+)?(?:[eE][+-]?\\d+)?)',
    // keywords
    '(true|false|null)',
    // brackets
    '([\\{\\}\\[\\]])',
    // punctuation
    '([,:])',
    // whitespace (including newlines — keep as single token per run)
    '(\\s+)',
  ].join('|'),
  'g',
)

export function tokenize(src: string): Token[] {
  const tokens: Token[] = []
  let depth   = 0
  let lastMeaningful: Token | null = null

  TOKEN_RE.lastIndex = 0

  let m: RegExpExecArray | null
  while ((m = TOKEN_RE.exec(src)) !== null) {
    const raw = m[0]

    if (m[1] !== undefined) {
      // ── String ──────────────────────────────────────────────────────────────
      const inner = raw.slice(1, -1)  // strip surrounding quotes

      // A string is a key if the previous meaningful token was ',' or '{' or
      // there is no previous meaningful token and we're inside an object (depth > 0).
      // More precisely: a string followed by ':' is a key — but we don't have
      // look-ahead here, so we use a two-pass approach: mark tentatively, then
      // convert on seeing ':'.
      // Simple heuristic: if lastMeaningful was '{' or ',' treat next string as key.
      const isKey =
        lastMeaningful === null ||
        (lastMeaningful.type === 'bracket' && (lastMeaningful.raw === '{')) ||
        (lastMeaningful.type === 'punctuation' && lastMeaningful.raw === ',')

      const tok: Token = {
        type:   isKey ? 'key' : 'string',
        raw,
        value:  inner,
        cdxKey: isKey ? CDX_KEYWORDS.has(inner) : false,
        isPurl: !isKey && inner.startsWith('pkg:'),
      }
      tokens.push(tok)
      lastMeaningful = tok

    } else if (m[2] !== undefined) {
      // ── Number ──────────────────────────────────────────────────────────────
      const tok: Token = { type: 'number', raw, value: raw }
      tokens.push(tok)
      lastMeaningful = tok

    } else if (m[3] !== undefined) {
      // ── Keyword ─────────────────────────────────────────────────────────────
      const tok: Token = { type: 'keyword', raw, value: raw }
      tokens.push(tok)
      lastMeaningful = tok

    } else if (m[4] !== undefined) {
      // ── Bracket ─────────────────────────────────────────────────────────────
      const isOpen = raw === '{' || raw === '['
      if (!isOpen) depth = Math.max(0, depth - 1)
      const tok: Token = { type: 'bracket', raw, value: raw, depth }
      tokens.push(tok)
      lastMeaningful = tok
      if (isOpen) depth++

    } else if (m[5] !== undefined) {
      // ── Punctuation ─────────────────────────────────────────────────────────
      const tok: Token = { type: 'punctuation', raw, value: raw }
      tokens.push(tok)
      lastMeaningful = tok

    } else if (m[6] !== undefined) {
      // ── Whitespace ──────────────────────────────────────────────────────────
      tokens.push({ type: 'whitespace', raw, value: raw })
      // don't update lastMeaningful
    }
  }

  // ── Second pass: re-classify strings followed by ':' as keys ────────────────
  // This corrects the heuristic above for edge cases like nested arrays of objects.
  for (let i = 0; i < tokens.length - 1; i++) {
    if (tokens[i].type === 'string') {
      // Look ahead skipping whitespace
      let j = i + 1
      while (j < tokens.length && tokens[j].type === 'whitespace') j++
      if (j < tokens.length && tokens[j].raw === ':') {
        tokens[i].type   = 'key'
        tokens[i].cdxKey = CDX_KEYWORDS.has(tokens[i].value)
        tokens[i].isPurl = false
      }
    }
  }

  return tokens
}

// ── Line splitter ─────────────────────────────────────────────────────────────
// Returns tokens grouped by line so the renderer can build <div> rows.

export type TokenLine = Token[]

export function splitIntoLines(tokens: Token[]): TokenLine[] {
  const lines: TokenLine[] = [[]]
  for (const tok of tokens) {
    if (tok.type === 'whitespace' && tok.raw.includes('\n')) {
      // Split on each newline
      const parts = tok.raw.split('\n')
      for (let i = 0; i < parts.length; i++) {
        if (i > 0) lines.push([])
        if (parts[i].length > 0) {
          lines[lines.length - 1].push({ ...tok, raw: parts[i], value: parts[i] })
        }
      }
    } else {
      lines[lines.length - 1].push(tok)
    }
  }
  // Remove trailing empty line if present
  if (lines[lines.length - 1].length === 0) lines.pop()
  return lines
}
