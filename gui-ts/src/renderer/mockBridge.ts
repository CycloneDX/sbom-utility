// SPDX-License-Identifier: Apache-2.0
/**
 * mockBridge.ts — browser-only stub for window.sbomBridge
 *
 * Injected automatically when the app is loaded outside of Electron
 * (i.e. directly in a browser via `npm run dev:browser`).
 *
 * File open/read use the browser's native <input type="file"> picker so
 * you can load a real JSON BOM file from disk.  IPC calls that would
 * normally run the sbom-utility CLI return a clearly labelled placeholder.
 *
 * This file is NEVER bundled into the production build — it is imported
 * only from main.tsx behind an `if (!window.sbomBridge)` guard.
 */

import type { SbomBridge, BomInfo, RunResult } from '../preload/index'

// ── File picker helpers ───────────────────────────────────────────────────────

/**
 * Show a browser <input type="file"> picker and resolve with the chosen File,
 * or null if the user cancels.
 */
function pickFile(accept = ''): Promise<File | null> {
  return new Promise(resolve => {
    const input = document.createElement('input')
    input.type   = 'file'
    input.accept = accept
    // Some browsers need the element in the DOM to fire 'change' reliably
    input.style.display = 'none'
    document.body.appendChild(input)
    input.addEventListener('change', () => {
      document.body.removeChild(input)
      resolve(input.files?.[0] ?? null)
    })
    // Cancelled: focus returns to window without a change event
    window.addEventListener('focus', function onFocus() {
      window.removeEventListener('focus', onFocus)
      // Give 'change' a chance to fire first
      setTimeout(() => {
        if (document.body.contains(input)) {
          document.body.removeChild(input)
          resolve(null)
        }
      }, 300)
    }, { once: true })
    input.click()
  })
}

/** Read a File object as a UTF-8 string. */
function readFileAsText(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload  = () => resolve(reader.result as string)
    reader.onerror = () => reject(reader.error)
    reader.readAsText(file)
  })
}

// ── In-memory store: path → content (keyed by fake absolute path) ─────────────
// Allows readFile() to return the same content after openFile() loads it.
const fileStore = new Map<string, string>()

// ── Save handle store: path → FileSystemFileHandle ────────────────────────────
// Bridges saveFileDialog() and writeFile() when showSaveFilePicker is used.
const saveHandleStore = new Map<string, FileSystemFileHandle>()

// ── Shared helpers ────────────────────────────────────────────────────────────

const ok = (stdout: string): RunResult => ({ stdout, stderr: '', code: 0 })

// ── BOM parsing helpers ───────────────────────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type BomJson = Record<string, any>

function parseBom(filePath: string): BomJson | null {
  const content = fileStore.get(filePath)
  if (!content) return null
  try { return JSON.parse(content) } catch { return null }
}

/**
 * Apply a --where filter string (key=regex,key2=regex2,…) to an object.
 * Returns true if the object passes all filters (or if where is blank).
 */
function applyWhere(obj: BomJson, where: string): boolean {
  if (!where.trim()) return true
  // Split on commas that are NOT inside a regex character class [...] — simple heuristic
  const pairs = where.split(/,(?![^\[]*\])/)
  for (const pair of pairs) {
    const eqIdx = pair.indexOf('=')
    if (eqIdx === -1) continue
    const key = pair.slice(0, eqIdx).trim()
    const pattern = pair.slice(eqIdx + 1).trim()
    // Map component field names to JSON keys
    const fieldMap: Record<string, string[]> = {
      'bom-ref': ['bom-ref'], 'group': ['group'], 'type': ['type'],
      'name': ['name'], 'version': ['version'], 'description': ['description'],
      'copyright': ['copyright'], 'purl': ['purl'], 'cpe': ['cpe'],
      'scope': ['scope'],
    }
    const jsonKeys = fieldMap[key] ?? [key]
    const re = new RegExp(pattern, 'i')
    const matches = jsonKeys.some(k => re.test(String(obj[k] ?? '')))
    if (!matches) return false
  }
  return true
}

/** Extract SPDX/expression license IDs from a CycloneDX licenses array. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function extractLicenseIds(licenses: any[]): string[] {
  if (!Array.isArray(licenses)) return []
  const ids: string[] = []
  for (const entry of licenses) {
    if (entry?.license?.id)         ids.push(entry.license.id)
    else if (entry?.license?.name)  ids.push(entry.license.name)
    else if (entry?.expression)     ids.push(entry.expression)
  }
  return ids
}

// ── listComponents implementation ────────────────────────────────────────────

function browserListComponents(params: { filePath: string; format?: string; where?: string; summary?: boolean }): RunResult {
  const bom = parseBom(params.filePath)
  if (!bom) return ok('[browser-dev] Could not parse BOM file.\n')

  const components: BomJson[] = Array.isArray(bom.components) ? bom.components : []
  if (components.length === 0) return ok('(no components found)\n')

  const where = params.where ?? ''
  const fmt   = params.format ?? 'txt'

  const filtered = components.filter(c => applyWhere(c, where))
  if (filtered.length === 0) return ok('(no components match the filter)\n')

  if (params.summary) {
    // Summary: count by type
    const counts: Record<string, number> = {}
    for (const c of filtered) {
      const t = c.type ?? 'unknown'
      counts[t] = (counts[t] ?? 0) + 1
    }
    const lines = Object.entries(counts).map(([t, n]) => `${t}: ${n}`)
    lines.unshift(`Total components: ${filtered.length}`)
    return ok(lines.join('\n') + '\n')
  }

  if (fmt === 'csv') {
    const header = 'bom-ref,type,group,name,version,purl'
    const rows = filtered.map(c =>
      [c['bom-ref'], c.type, c.group, c.name, c.version, c.purl]
        .map(v => (v == null ? '' : `"${String(v).replace(/"/g, '""')}"`))
        .join(',')
    )
    return ok([header, ...rows].join('\n') + '\n')
  }

  if (fmt === 'md') {
    const header = '| bom-ref | type | name | version | purl |'
    const sep    = '|---------|------|------|---------|------|'
    const rows = filtered.map(c =>
      `| ${c['bom-ref'] ?? ''} | ${c.type ?? ''} | ${c.name ?? ''} | ${c.version ?? ''} | ${c.purl ?? ''} |`
    )
    return ok([header, sep, ...rows].join('\n') + '\n')
  }

  // Default: txt
  const lines = filtered.map((c, i) => {
    const parts: string[] = [`[${i + 1}]`]
    if (c.type)        parts.push(`type=${c.type}`)
    if (c['bom-ref'])  parts.push(`bom-ref=${c['bom-ref']}`)
    if (c.group)       parts.push(`group=${c.group}`)
    if (c.name)        parts.push(`name=${c.name}`)
    if (c.version)     parts.push(`version=${c.version}`)
    if (c.purl)        parts.push(`purl=${c.purl}`)
    const licIds = extractLicenseIds(c.licenses)
    if (licIds.length) parts.push(`licenses=${licIds.join(', ')}`)
    return parts.join('  ')
  })
  lines.unshift(`Components (${filtered.length}):`)
  return ok(lines.join('\n') + '\n')
}

// ── listLicenses implementation ───────────────────────────────────────────────

function browserListLicenses(params: { filePath: string; format?: string; where?: string; summary?: boolean }): RunResult {
  const bom = parseBom(params.filePath)
  if (!bom) return ok('[browser-dev] Could not parse BOM file.\n')

  const components: BomJson[] = Array.isArray(bom.components) ? bom.components : []
  const where = params.where ?? ''
  const fmt   = params.format ?? 'txt'

  // Collect all license entries across components
  type LicEntry = { component: string; purl: string; licenseType: string; license: string }
  const entries: LicEntry[] = []

  for (const c of components) {
    const licIds = extractLicenseIds(c.licenses)
    if (licIds.length === 0) continue
    for (const lic of licIds) {
      const entry: LicEntry = {
        component:   c.name ?? c['bom-ref'] ?? '',
        purl:        c.purl ?? '',
        licenseType: 'id',
        license:     lic,
      }
      // Apply where filter
      const filterObj: BomJson = {
        license:       entry.license,
        'resource-name': entry.component,
        'bom-ref':     c['bom-ref'] ?? '',
        purl:          entry.purl,
        'license-type': entry.licenseType,
      }
      if (!applyWhere(filterObj, where)) continue
      entries.push(entry)
    }
  }

  if (entries.length === 0) return ok('(no licenses found)\n')

  if (params.summary) {
    const counts: Record<string, number> = {}
    for (const e of entries) {
      counts[e.license] = (counts[e.license] ?? 0) + 1
    }
    const lines = Object.entries(counts)
      .sort(([, a], [, b]) => b - a)
      .map(([lic, n]) => `${lic}: ${n}`)
    lines.unshift(`Total license entries: ${entries.length}`)
    return ok(lines.join('\n') + '\n')
  }

  if (fmt === 'csv') {
    const header = 'component,purl,license'
    const rows = entries.map(e =>
      [e.component, e.purl, e.license]
        .map(v => `"${v.replace(/"/g, '""')}"`)
        .join(',')
    )
    return ok([header, ...rows].join('\n') + '\n')
  }

  if (fmt === 'json') {
    return ok(JSON.stringify(entries, null, 2) + '\n')
  }

  if (fmt === 'md') {
    const header = '| component | purl | license |'
    const sep    = '|-----------|------|---------|'
    const rows = entries.map(e => `| ${e.component} | ${e.purl} | ${e.license} |`)
    return ok([header, sep, ...rows].join('\n') + '\n')
  }

  // txt
  const lines = entries.map((e, i) =>
    `[${i + 1}]  component=${e.component}  license=${e.license}${e.purl ? '  purl=' + e.purl : ''}`
  )
  lines.unshift(`Licenses (${entries.length}):`)
  return ok(lines.join('\n') + '\n')
}

// ── listResources implementation ─────────────────────────────────────────────

function browserListResources(params: { filePath: string; format?: string; where?: string; resourceType?: string }): RunResult {
  const bom = parseBom(params.filePath)
  if (!bom) return ok('[browser-dev] Could not parse BOM file.\n')

  const where        = params.where ?? ''
  const fmt          = params.format ?? 'txt'
  const resourceType = params.resourceType ?? ''

  type ResEntry = { resourceType: string; 'bom-ref': string; group: string; name: string; version: string; description: string }
  const entries: ResEntry[] = []

  const addItems = (arr: BomJson[], type: string) => {
    for (const item of arr) {
      if (!applyWhere({ ...item, 'resource-type': type }, where)) continue
      entries.push({
        resourceType: type,
        'bom-ref':   item['bom-ref']     ?? '',
        group:       item.group          ?? '',
        name:        item.name           ?? '',
        version:     item.version        ?? '',
        description: item.description    ?? '',
      })
    }
  }

  if (!resourceType || resourceType === 'component') {
    addItems(Array.isArray(bom.components) ? bom.components : [], 'component')
  }
  if (!resourceType || resourceType === 'service') {
    addItems(Array.isArray(bom.services) ? bom.services : [], 'service')
  }

  if (entries.length === 0) return ok('(no resources found)\n')

  if (fmt === 'csv') {
    const header = 'resource-type,bom-ref,group,name,version'
    const rows = entries.map(e =>
      [e.resourceType, e['bom-ref'], e.group, e.name, e.version]
        .map(v => `"${v.replace(/"/g, '""')}"`)
        .join(',')
    )
    return ok([header, ...rows].join('\n') + '\n')
  }

  if (fmt === 'md') {
    const header = '| resource-type | bom-ref | group | name | version |'
    const sep    = '|---------------|---------|-------|------|---------|'
    const rows = entries.map(e =>
      `| ${e.resourceType} | ${e['bom-ref']} | ${e.group} | ${e.name} | ${e.version} |`
    )
    return ok([header, sep, ...rows].join('\n') + '\n')
  }

  // txt
  const lines = entries.map((e, i) => {
    const parts = [`[${i + 1}]  resource-type=${e.resourceType}`]
    if (e['bom-ref']) parts.push(`bom-ref=${e['bom-ref']}`)
    if (e.group)      parts.push(`group=${e.group}`)
    if (e.name)       parts.push(`name=${e.name}`)
    if (e.version)    parts.push(`version=${e.version}`)
    return parts.join('  ')
  })
  lines.unshift(`Resources (${entries.length}):`)
  return ok(lines.join('\n') + '\n')
}

// ── listVulnerabilities implementation ────────────────────────────────────────

function browserListVulnerabilities(params: { filePath: string; format?: string; where?: string; summary?: boolean }): RunResult {
  const bom = parseBom(params.filePath)
  if (!bom) return ok('[browser-dev] Could not parse BOM file.\n')

  const vulns: BomJson[] = Array.isArray(bom.vulnerabilities) ? bom.vulnerabilities : []
  if (vulns.length === 0) return ok('(no vulnerabilities found)\n')

  const where = params.where ?? ''
  const fmt   = params.format ?? 'txt'
  const filtered = vulns.filter(v => applyWhere(v, where))
  if (filtered.length === 0) return ok('(no vulnerabilities match the filter)\n')

  if (params.summary) {
    const bySev: Record<string, number> = {}
    for (const v of filtered) {
      const sev = v.ratings?.[0]?.severity ?? 'unknown'
      bySev[sev] = (bySev[sev] ?? 0) + 1
    }
    const lines = Object.entries(bySev).map(([s, n]) => `${s}: ${n}`)
    lines.unshift(`Total vulnerabilities: ${filtered.length}`)
    return ok(lines.join('\n') + '\n')
  }

  if (fmt === 'csv') {
    const header = 'id,severity,cvss-score,description'
    const rows = filtered.map(v =>
      [v.id, v.ratings?.[0]?.severity, v.ratings?.[0]?.score, v.description]
        .map(val => val == null ? '' : `"${String(val).replace(/"/g, '""')}"`)
        .join(',')
    )
    return ok([header, ...rows].join('\n') + '\n')
  }

  if (fmt === 'md') {
    const header = '| id | severity | score | description |'
    const sep    = '|----|----------|-------|-------------|'
    const rows = filtered.map(v =>
      `| ${v.id ?? ''} | ${v.ratings?.[0]?.severity ?? ''} | ${v.ratings?.[0]?.score ?? ''} | ${v.description ?? ''} |`
    )
    return ok([header, sep, ...rows].join('\n') + '\n')
  }

  const lines = filtered.map((v, i) => {
    const parts = [`[${i + 1}]  id=${v.id ?? ''}`]
    if (v.ratings?.[0]?.severity) parts.push(`severity=${v.ratings[0].severity}`)
    if (v.ratings?.[0]?.score)    parts.push(`score=${v.ratings[0].score}`)
    if (v.description)            parts.push(`description=${v.description}`)
    return parts.join('  ')
  })
  lines.unshift(`Vulnerabilities (${filtered.length}):`)
  return ok(lines.join('\n') + '\n')
}

// ── patch implementation ─────────────────────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type PatchRecord = { op: string; path: string; value?: any; from?: string }

/**
 * Resolve a RFC 6901 JSON Pointer path into an array of string keys.
 * e.g. "/metadata/component/properties/0" → ["metadata","component","properties","0"]
 */
function parsePatchPath(pointer: string): string[] {
  if (!pointer || pointer[0] !== '/') throw new Error(`Invalid JSON Pointer: "${pointer}"`)
  return pointer.slice(1).split('/').map(k => k.replace(/~1/g, '/').replace(/~0/g, '~'))
}

/** Walk to the parent container and final key, or throw on a missing intermediate. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function resolvePath(doc: any, keys: string[]): { parent: any; key: string } {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let cur: any = doc
  for (let i = 0; i < keys.length - 1; i++) {
    if (cur == null || typeof cur !== 'object') throw new Error(`Path not found at key "${keys[i]}"`)
    cur = Array.isArray(cur) ? cur[Number(keys[i])] : cur[keys[i]]
  }
  return { parent: cur, key: keys[keys.length - 1] }
}

function browserApplyPatch(params: { bomPath: string; patchPath: string }): RunResult {
  const bomContent   = fileStore.get(params.bomPath)
  const patchContent = fileStore.get(params.patchPath)

  if (!bomContent)   return { stdout: '', stderr: `[browser-dev] BOM file not found in store: "${params.bomPath}". Open it first.`,   code: 1 }
  if (!patchContent) return { stdout: '', stderr: `[browser-dev] Patch file not found in store: "${params.patchPath}". Open it first.`, code: 1 }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let doc: any
  let records: PatchRecord[]
  try { doc = JSON.parse(bomContent) }     catch (e) { return { stdout: '', stderr: `JSON parse error in BOM: ${e}`,   code: 1 } }
  try { records = JSON.parse(patchContent) } catch (e) { return { stdout: '', stderr: `JSON parse error in patch: ${e}`, code: 1 } }

  if (!Array.isArray(records)) return { stdout: '', stderr: 'Patch file must be a JSON array of operation objects.', code: 1 }

  for (const rec of records) {
    const keys = parsePatchPath(rec.path)
    const { parent, key } = resolvePath(doc, keys)

    switch (rec.op) {
      case 'add':
        if (Array.isArray(parent)) {
          const idx = key === '-' ? parent.length : Number(key)
          parent.splice(idx, 0, rec.value)
        } else {
          parent[key] = rec.value
        }
        break
      case 'remove':
        if (Array.isArray(parent)) {
          parent.splice(Number(key), 1)
        } else {
          delete parent[key]
        }
        break
      case 'replace':
        if (!(key in parent)) return { stdout: '', stderr: `replace: path "${rec.path}" does not exist.`, code: 1 }
        parent[key] = rec.value
        break
      case 'test': {
        const actual = parent[key]
        if (JSON.stringify(actual) !== JSON.stringify(rec.value))
          return { stdout: '', stderr: `test failed at "${rec.path}": expected ${JSON.stringify(rec.value)}, got ${JSON.stringify(actual)}`, code: 1 }
        break
      }
      default:
        return { stdout: '', stderr: `Unsupported patch op: "${rec.op}"`, code: 1 }
    }
  }

  return ok(JSON.stringify(doc, null, 4) + '\n')
}

// ── diff implementation ──────────────────────────────────────────────────────

function browserDiffBoms(params: { fileA: string; fileB: string }): RunResult {
  const contentA = fileStore.get(params.fileA)
  const contentB = fileStore.get(params.fileB)

  if (!contentA && !contentB) {
    return { stdout: '', stderr: `[browser-dev] Cannot read either BOM file. Open both files first.`, code: 1 }
  }
  if (!contentA) {
    return { stdout: '', stderr: `[browser-dev] Cannot read File A: "${params.fileA}". Open it first.`, code: 1 }
  }
  if (!contentB) {
    return { stdout: '', stderr: `[browser-dev] Cannot read File B: "${params.fileB}". Open it first.`, code: 1 }
  }

  // Normalise: parse → re-serialise with stable key order so pure whitespace
  // differences don't produce noise.
  let bomA: BomJson, bomB: BomJson
  try { bomA = JSON.parse(contentA) } catch (e: unknown) {
    return { stdout: '', stderr: `JSON parse error in File A: ${e instanceof Error ? e.message : String(e)}`, code: 1 }
  }
  try { bomB = JSON.parse(contentB) } catch (e: unknown) {
    return { stdout: '', stderr: `JSON parse error in File B: ${e instanceof Error ? e.message : String(e)}`, code: 1 }
  }

  const linesA = JSON.stringify(bomA, null, 2).split('\n')
  const linesB = JSON.stringify(bomB, null, 2).split('\n')

  if (linesA.join('\n') === linesB.join('\n')) {
    return ok('(no differences — BOM files are identical)\n')
  }

  // Myers-style unified diff (context=3)
  const CONTEXT = 3
  const diff = unifiedDiff(linesA, linesB, params.fileA, params.fileB, CONTEXT)
  // Non-zero exit code signals differences (mirrors real sbom-utility behaviour)
  return { stdout: diff, stderr: '', code: 1 }
}

/**
 * Compute a unified diff between two line arrays using Myers' O(nd) algorithm.
 *
 * Unlike the previous LCS approach (O(m×n) memory), Myers' algorithm only needs
 * O(d) space where d = number of edit operations, so it handles files of any
 * size as long as the diff itself is not enormous.
 */
function unifiedDiff(linesA: string[], linesB: string[], labelA: string, labelB: string, ctx: number): string {
  type Op = { kind: 'eq' | 'del' | 'ins'; a: number; b: number }
  const ops = myersDiff(linesA, linesB)

  // Group ops into hunks with `ctx` lines of context on each side
  const hunks: string[][] = []
  let hunk: string[] = []
  let pendingEq: Op[] = []
  let hunkStartA = 0, hunkStartB = 0
  let hunkCountA = 0, hunkCountB = 0
  let inHunk = false

  const flushHunk = () => {
    if (hunk.length === 0) return
    hunks.push([`@@ -${hunkStartA + 1},${hunkCountA} +${hunkStartB + 1},${hunkCountB} @@`, ...hunk])
    hunk = []; hunkCountA = 0; hunkCountB = 0; inHunk = false
  }

  for (const op of ops) {
    if (op.kind === 'eq') {
      pendingEq.push(op)
      if (pendingEq.length > ctx * 2 + 1) {
        // Enough gap to close the current hunk and start a fresh leading context
        if (inHunk) {
          for (let c = 0; c < ctx && c < pendingEq.length; c++) {
            hunk.push(' ' + linesA[pendingEq[c].a])
            hunkCountA++; hunkCountB++
          }
          flushHunk()
        }
        pendingEq = pendingEq.slice(-ctx)
      }
    } else {
      // Emit leading context
      const ctxOps = pendingEq.slice(-ctx)
      if (!inHunk) {
        hunkStartA = ctxOps.length > 0 ? ctxOps[0].a : op.a
        hunkStartB = ctxOps.length > 0 ? ctxOps[0].b : op.b
        inHunk = true
      }
      for (const eq of ctxOps) {
        hunk.push(' ' + linesA[eq.a])
        hunkCountA++; hunkCountB++
      }
      pendingEq = []

      if (op.kind === 'del') {
        hunk.push('-' + linesA[op.a])
        hunkCountA++
      } else {
        hunk.push('+' + linesB[op.b])
        hunkCountB++
      }
    }
  }
  // Flush trailing context
  if (inHunk) {
    for (let c = 0; c < ctx && c < pendingEq.length; c++) {
      hunk.push(' ' + linesA[pendingEq[c].a])
      hunkCountA++; hunkCountB++
    }
    flushHunk()
  }

  if (hunks.length === 0) return '(no differences)\n'

  const nameA = labelA.split('/').pop() ?? labelA
  const nameB = labelB.split('/').pop() ?? labelB
  const header = `--- ${nameA}\n+++ ${nameB}\n`
  return header + hunks.map(h => h.join('\n')).join('\n') + '\n'
}

/**
 * Myers' diff algorithm — returns a flat list of edit operations in order.
 *
 * Time:   O(n·d)  where n = max(m, len_b), d = edit distance
 * Memory: O(n·d)  for the trace (one V snapshot per d-step)
 *
 * Reference: E.W. Myers, "An O(ND) Difference Algorithm and Its Variations",
 * Algorithmica 1(2), 1986.
 */
function myersDiff(
  a: string[],
  b: string[],
): { kind: 'eq' | 'del' | 'ins'; a: number; b: number }[] {
  const m = a.length, n = b.length
  const max = m + n

  // V[k] = furthest x reached on diagonal k (k = x − y)
  // We store V indexed as V[k + max] to allow negative k.
  const V = new Int32Array(2 * max + 1)

  // Snapshots of V at each d-step, needed for backtracking
  const trace: Int32Array[] = []

  outer: for (let d = 0; d <= max; d++) {
    trace.push(V.slice())
    for (let k = -d; k <= d; k += 2) {
      const ki = k + max
      let x: number
      if (k === -d || (k !== d && V[ki - 1] < V[ki + 1])) {
        x = V[ki + 1]        // move down (insertion)
      } else {
        x = V[ki - 1] + 1    // move right (deletion)
      }
      let y = x - k
      // Extend along the diagonal (matching lines)
      while (x < m && y < n && a[x] === b[y]) { x++; y++ }
      V[ki] = x
      if (x >= m && y >= n) break outer
    }
  }

  // Backtrack through the trace to reconstruct operations
  type Op = { kind: 'eq' | 'del' | 'ins'; a: number; b: number }
  const ops: Op[] = []
  let x = m, y = n

  for (let d = trace.length - 1; d >= 0; d--) {
    const Vd = trace[d]
    const k  = x - y
    const ki = k + max

    // Which move reached diagonal k at step d?
    const insertMove = k === -d || (k !== d && Vd[ki - 1] < Vd[ki + 1])
    const prevK = insertMove ? k + 1 : k - 1
    const prevX = Vd[prevK + max]
    const prevY = prevX - prevK

    // The snake start (after the single edit move)
    const snakeX = insertMove ? prevX     : prevX + 1
    const snakeY = insertMove ? prevY + 1 : prevY

    // Equal lines along the diagonal snake: [snakeX..x) paired with [snakeY..y)
    // Emit in reverse order (will be corrected by ops.reverse() at the end)
    for (let ex = x - 1; ex >= snakeX; ex--) {
      ops.push({ kind: 'eq', a: ex, b: snakeY + (ex - snakeX) })
    }

    // The single edit that preceded the snake
    if (d > 0) {
      if (insertMove) {
        ops.push({ kind: 'ins', a: prevX, b: prevY })
      } else {
        ops.push({ kind: 'del', a: prevX, b: prevY })
      }
    }

    x = prevX; y = prevY
  }

  ops.reverse()
  return ops
}

// ── validate implementation ───────────────────────────────────────────────────

function browserValidate(filePath: string): RunResult {
  const content = fileStore.get(filePath)
  if (!content) return { stdout: '', stderr: 'Could not read file from browser store.', code: 1 }
  let bom: BomJson
  try {
    bom = JSON.parse(content)
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e)
    return { stdout: '', stderr: `JSON parse error: ${msg}`, code: 1 }
  }
  const issues: string[] = []
  if (!bom.bomFormat)    issues.push('Missing required field: bomFormat')
  if (!bom.specVersion)  issues.push('Missing required field: specVersion')
  if (issues.length) {
    return { stdout: '', stderr: issues.join('\n'), code: 1 }
  }
  const numComponents = Array.isArray(bom.components) ? bom.components.length : 0
  return ok(
    `[browser-dev] BOM structure OK (basic check only — JSON is well-formed).\n` +
    `bomFormat: ${bom.bomFormat}  specVersion: ${bom.specVersion}\n` +
    `components: ${numComponents}\n`
  )
}

// ── Bridge implementation ─────────────────────────────────────────────────────

export const mockBridge: SbomBridge = {
  // ── File system ────────────────────────────────────────────────────────────

  openFile: async () => {
    const file = await pickFile('.json,.xml')
    if (!file) return null
    const content = await readFileAsText(file)
    // Fabricate an absolute-style path using the file name
    const fakePath = `/browser-local/${file.name}`
    fileStore.set(fakePath, content)
    return fakePath
  },

  readFile: async (filePath: string) => {
    const stored = fileStore.get(filePath)
    if (stored !== undefined) return stored
    throw new Error(`[browser-dev] readFile: no content cached for "${filePath}"`)
  },

  saveFileDialog: async (_defaultPath: string) => {
    // Use the modern File System Access API when available (Chrome/Edge 86+).
    // Fall back to a simple prompt so the user can at least provide a filename.
    if (typeof (window as unknown as { showSaveFilePicker?: unknown }).showSaveFilePicker === 'function') {
      const suggestedName = _defaultPath.split('/').pop() ?? 'sbom-edited.json'
      try {
        const handle = await (window as unknown as {
          showSaveFilePicker(opts: {
            suggestedName: string
            types: { description: string; accept: Record<string, string[]> }[]
          }): Promise<FileSystemFileHandle>
        }).showSaveFilePicker({
          suggestedName,
          types: [
            { description: 'JSON files', accept: { 'application/json': ['.json'] } },
            { description: 'All files',  accept: { '*/*': [] } },
          ],
        })
        // Store the handle under a fabricated path derived from the file name
        const fakePath = `/browser-local/${handle.name}`
        // Attach the handle so writeFile can use it
        saveHandleStore.set(fakePath, handle)
        return fakePath
      } catch {
        // User cancelled (AbortError) or API unavailable
        return null
      }
    }
    // Fallback: prompt for a new filename
    const suggestion = _defaultPath.split('/').pop() ?? 'sbom-edited.json'
    const name = window.prompt('Save as filename:', suggestion)
    if (!name) return null
    return `/browser-local/${name}`
  },

  writeFile: async (_path: string, content: string) => {
    // If we have a FileSystemFileHandle from showSaveFilePicker, write through it
    const handle = saveHandleStore.get(_path)
    if (handle) {
      const writable = await handle.createWritable()
      await writable.write(content)
      await writable.close()
      saveHandleStore.delete(_path)
      fileStore.set(_path, content)
      return
    }
    // Fallback: trigger a browser download of the edited content
    const blob = new Blob([content], { type: 'application/json' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href     = url
    a.download = _path.split('/').pop() ?? 'sbom-edited.json'
    a.click()
    URL.revokeObjectURL(url)
    fileStore.set(_path, content)
  },

  // ── BOM metadata ───────────────────────────────────────────────────────────
  getBomInfo: (filePath: string): Promise<BomInfo> => {
    const content = fileStore.get(filePath) ?? ''
    const specMatch = content.match(/"specVersion"\s*:\s*"([^"]+)"/)
    const fmtMatch  = content.match(/"bomFormat"\s*:\s*"([^"]+)"/)
    return Promise.resolve({
      filePath,
      specVersion: specMatch?.[1] ?? '',
      format:      fmtMatch?.[1]  ?? '',
    })
  },

  // ── Commands ───────────────────────────────────────────────────────────────
  validate:            (p) => Promise.resolve(browserValidate(p.filePath)),
  listLicenses:        (p) => Promise.resolve(browserListLicenses(p)),
  listComponents:      (p) => Promise.resolve(browserListComponents(p)),
  listResources:       (p) => Promise.resolve(browserListResources(p)),
  listVulnerabilities: (p) => Promise.resolve(browserListVulnerabilities(p)),
  diffBoms:            (p) => Promise.resolve(browserDiffBoms(p)),
  applyPatch:          (p) => Promise.resolve(browserApplyPatch(p)),

  // ── App ────────────────────────────────────────────────────────────────────
  getVersion: () => Promise.resolve('0.16.0-browser-dev'),

  isDarkMode: () => Promise.resolve(
    window.matchMedia('(prefers-color-scheme: dark)').matches
  ),
}
