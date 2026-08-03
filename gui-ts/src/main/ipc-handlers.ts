// SPDX-License-Identifier: Apache-2.0
/**
 * Electron Main Process — IPC Handlers (src/main/ipc-handlers.ts)
 *
 * All handlers that invoke the sbom-utility CLI binary live here.
 * The binary path is resolved once in index.ts and passed in via BridgeConfig
 * so that renderer-supplied input can NEVER control which executable is run.
 *
 * Input validation rules:
 *   - filePath   : must be an absolute path and must pass a basic path-traversal check.
 *   - flag values: only known safe string values are forwarded to the CLI.
 *   - All arguments are passed as an argv array — no shell interpolation.
 */

import { ipcMain, dialog } from 'electron'
import { execFile }  from 'child_process'
import * as path     from 'path'
import * as fs       from 'fs'

// ── Types ─────────────────────────────────────────────────────────────────────

export interface BridgeConfig {
  binaryPath:        string
  configPath:        string
  licensePolicyPath: string
}

interface ExecResult {
  stdout: string
  stderr: string
  code:   number
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Validate that a file path is absolute and does not contain obvious
 * path-traversal sequences.  Throws if the path is unsafe.
 */
function validateFilePath(p: unknown): string {
  if (typeof p !== 'string' || p.trim() === '') {
    throw new Error('filePath must be a non-empty string')
  }
  if (!path.isAbsolute(p)) {
    throw new Error('filePath must be an absolute path')
  }
  // Reject ../ traversal sequences after normalisation
  const normalised = path.normalize(p)
  if (normalised.includes('..')) {
    throw new Error('filePath must not contain path-traversal sequences')
  }
  if (!fs.existsSync(normalised)) {
    throw new Error(`File not found: ${normalised}`)
  }
  return normalised
}

/**
 * Validate a destination path for writing.  Must be absolute, no traversal,
 * and the parent directory must exist.  The file itself need not exist yet.
 */
function validateWritePath(p: unknown): string {
  if (typeof p !== 'string' || p.trim() === '') {
    throw new Error('filePath must be a non-empty string')
  }
  if (!path.isAbsolute(p)) {
    throw new Error('filePath must be an absolute path')
  }
  const normalised = path.normalize(p)
  if (normalised.includes('..')) {
    throw new Error('filePath must not contain path-traversal sequences')
  }
  const dir = path.dirname(normalised)
  if (!fs.existsSync(dir)) {
    throw new Error(`Directory does not exist: ${dir}`)
  }
  return normalised
}

/**
 * Validate that a value is one of a fixed set of allowed strings.
 * Returns the value unchanged or throws.
 */
function allowList<T extends string>(value: unknown, allowed: T[], defaultValue: T): T {
  if (value === undefined || value === null || value === '') return defaultValue
  if (typeof value !== 'string')   throw new Error('Expected a string value')
  if (!allowed.includes(value as T)) throw new Error(`Value "${value}" is not in the allowed list`)
  return value as T
}

/**
 * Run the sbom-utility binary with the given arguments.
 * Returns stdout, stderr, and exit code.
 * No shell is used; args are passed as an array.
 */
function runBinary(binaryPath: string, args: string[], env: NodeJS.ProcessEnv): Promise<ExecResult> {
  return new Promise((resolve) => {
    const child = execFile(binaryPath, args, { env, maxBuffer: 32 * 1024 * 1024 }, (err, stdout, stderr) => {
      const exitCode = child.exitCode ?? (typeof err?.code === 'number' ? err.code : 0)
      resolve({
        stdout: stdout ?? '',
        stderr: stderr ?? '',
        code:   exitCode,
      })
    })
  })
}

// ── Format maps ───────────────────────────────────────────────────────────────

const ALLOWED_FORMATS_FULL  = ['txt', 'csv', 'json', 'md'] as const
const ALLOWED_FORMATS_SHORT = ['txt', 'csv', 'md']         as const
type FormatFull  = typeof ALLOWED_FORMATS_FULL[number]
type FormatShort = typeof ALLOWED_FORMATS_SHORT[number]

// ── Diff / patch params ───────────────────────────────────────────────────────

export interface DiffParams {
  fileA: string
  fileB: string
}

export interface PatchParams {
  bomPath:   string
  patchPath: string
}

// ── Handler registration ──────────────────────────────────────────────────────

export function registerIpcHandlers(config: BridgeConfig): void {
  const { binaryPath, configPath, licensePolicyPath } = config

  // Base env for all child processes: inherit only what is needed.
  // Deliberately strip HOME-derived config that could be injected via env.
  const baseEnv: NodeJS.ProcessEnv = {
    PATH: process.env['PATH'],
  }

  // ── bom:info ─────────────────────────────────────────────────────────────
  // Returns { format, specVersion, filePath } by running `validate --list-schema`
  // which prints the detected schema line on stdout even when validation fails.
  ipcMain.handle('bom:info', async (_event, filePath: unknown) => {
    const safe = validateFilePath(filePath)
    const args = [
      'validate',
      '--input-file', safe,
      '--config-schema',         configPath,
      '--config-license',        licensePolicyPath,
      '--format', 'txt',
      '--error-limit', '1',
    ]
    const res = await runBinary(binaryPath, args, baseEnv)
    // Parse the "schema:" line from combined output to extract spec version.
    const combined = res.stdout + res.stderr
    const specMatch = combined.match(/schema\s+version[:\s]+([0-9.]+)/i)
    const fmtMatch  = combined.match(/(CycloneDX|SPDX)/i)
    return {
      filePath:    safe,
      specVersion: specMatch?.[1] ?? '',
      format:      fmtMatch?.[1]  ?? '',
    }
  })

  // ── bom:validate ─────────────────────────────────────────────────────────
  ipcMain.handle('bom:validate', async (_event, params: unknown) => {
    const p = params as Record<string, unknown>
    const safe      = validateFilePath(p['filePath'])
    const variant   = typeof p['variant']    === 'string' ? p['variant']    : ''
    const force     = typeof p['forceSchema'] === 'string' ? p['forceSchema'] : ''
    const maxErrors = typeof p['maxErrors']  === 'number'  ? p['maxErrors']  : 10
    const showVals  = p['showValues'] === true

    const args = [
      'validate',
      '--input-file', safe,
      '--config-schema',  configPath,
      '--config-license', licensePolicyPath,
      '--format', 'txt',
      '--error-limit', String(Math.min(Math.max(1, maxErrors), 200)),
    ]
    if (variant)  args.push('--variant',    variant)
    if (force)    args.push('--force',      force)
    if (showVals) args.push('--error-value')

    const res = await runBinary(binaryPath, args, baseEnv)
    return { stdout: res.stdout, stderr: res.stderr, code: res.code }
  })

  // ── bom:listLicenses ─────────────────────────────────────────────────────
  ipcMain.handle('bom:listLicenses', async (_event, params: unknown) => {
    const p      = params as Record<string, unknown>
    const safe   = validateFilePath(p['filePath'])
    const fmt    = allowList<FormatFull>(p['format'], [...ALLOWED_FORMATS_FULL], 'txt')
    const where  = typeof p['where']   === 'string' ? p['where']   : ''
    const summary = p['summary'] === true

    const args = [
      'license', 'list',
      '--input-file', safe,
      '--config-schema',  configPath,
      '--config-license', licensePolicyPath,
      '--format', fmt,
    ]
    if (summary) args.push('--summary')
    if (where)   args.push('--where', where)

    const res = await runBinary(binaryPath, args, baseEnv)
    return { stdout: res.stdout, stderr: res.stderr, code: res.code }
  })

  // ── bom:listComponents ───────────────────────────────────────────────────
  ipcMain.handle('bom:listComponents', async (_event, params: unknown) => {
    const p      = params as Record<string, unknown>
    const safe   = validateFilePath(p['filePath'])
    const fmt    = allowList<FormatShort>(p['format'], [...ALLOWED_FORMATS_SHORT], 'txt')
    const where  = typeof p['where']   === 'string' ? p['where']   : ''
    const summary = p['summary'] === true

    const args = [
      'component', 'list',
      '--input-file', safe,
      '--config-schema',  configPath,
      '--config-license', licensePolicyPath,
      '--format', fmt,
    ]
    if (summary) args.push('--summary')
    if (where)   args.push('--where', where)

    const res = await runBinary(binaryPath, args, baseEnv)
    return { stdout: res.stdout, stderr: res.stderr, code: res.code }
  })

  // ── bom:listResources ────────────────────────────────────────────────────
  ipcMain.handle('bom:listResources', async (_event, params: unknown) => {
    const p      = params as Record<string, unknown>
    const safe   = validateFilePath(p['filePath'])
    const fmt    = allowList<FormatShort>(p['format'], [...ALLOWED_FORMATS_SHORT], 'txt')
    const where  = typeof p['where']   === 'string' ? p['where']   : ''
    const rtype  = allowList<string>(p['resourceType'], ['', 'component', 'service'], '')

    const args = [
      'resource', 'list',
      '--input-file', safe,
      '--config-schema',  configPath,
      '--config-license', licensePolicyPath,
      '--format', fmt,
    ]
    if (rtype) args.push('--type',  rtype)
    if (where) args.push('--where', where)

    const res = await runBinary(binaryPath, args, baseEnv)
    return { stdout: res.stdout, stderr: res.stderr, code: res.code }
  })

  // ── bom:listVulnerabilities ──────────────────────────────────────────────
  ipcMain.handle('bom:listVulnerabilities', async (_event, params: unknown) => {
    const p      = params as Record<string, unknown>
    const safe   = validateFilePath(p['filePath'])
    const fmt    = allowList<FormatFull>(p['format'], [...ALLOWED_FORMATS_FULL], 'txt')
    const where  = typeof p['where']   === 'string' ? p['where']   : ''
    const summary = p['summary'] === true

    const args = [
      'vulnerability', 'list',
      '--input-file', safe,
      '--config-schema',  configPath,
      '--config-license', licensePolicyPath,
      '--format', fmt,
    ]
    if (summary) args.push('--summary')
    if (where)   args.push('--where', where)

    const res = await runBinary(binaryPath, args, baseEnv)
    return { stdout: res.stdout, stderr: res.stderr, code: res.code }
  })

  // ── fs:readFile ──────────────────────────────────────────────────────────
  // Read a file's contents for the View tab.  Only allowed for files the user
  // has explicitly opened via the OS file dialog (filePath validated above).
  ipcMain.handle('fs:readFile', async (_event, filePath: unknown) => {
    const safe = validateFilePath(filePath)
    return fs.readFileSync(safe, 'utf-8')
  })

  // ── dialog:saveFile ───────────────────────────────────────────────────────
  // Shows the native Save dialog pre-populated with `defaultPath`.
  // Returns the chosen path on confirmation, or null on cancel.
  ipcMain.handle('dialog:saveFile', async (_event, defaultPath: unknown) => {
    if (typeof defaultPath !== 'string' || !defaultPath.trim()) {
      throw new Error('defaultPath must be a non-empty string')
    }
    const result = await dialog.showSaveDialog({
      defaultPath,
      filters: [
        { name: 'JSON files', extensions: ['json'] },
        { name: 'All files',  extensions: ['*']    },
      ],
    })
    return result.canceled ? null : result.filePath ?? null
  })

  // ── fs:writeFile ──────────────────────────────────────────────────────────
  // Write text content to a validated absolute path.
  ipcMain.handle('fs:writeFile', async (_event, filePath: unknown, content: unknown) => {
    const safe = validateWritePath(filePath)
    if (typeof content !== 'string') {
      throw new Error('content must be a string')
    }
    fs.writeFileSync(safe, content, 'utf-8')
  })

  // ── bom:diff ─────────────────────────────────────────────────────────────
  // Runs: sbom-utility diff --input-file <A> --diff-file <B> --format text
  ipcMain.handle('bom:diff', async (_event, params: unknown) => {
    const p     = params as Record<string, unknown>
    const safeA = validateFilePath(p['fileA'])
    const safeB = validateFilePath(p['fileB'])

    const args = [
      'diff',
      '--input-file', safeA,
      '--diff-file',  safeB,
      '--format', 'text',
    ]
    const res = await runBinary(binaryPath, args, baseEnv)
    return { stdout: res.stdout, stderr: res.stderr, code: res.code }
  })

  // ── bom:patch ────────────────────────────────────────────────────────────
  // Runs: sbom-utility patch --input-file <bom> --patch-file <patch>
  // Output (patched BOM JSON) arrives on stdout.
  ipcMain.handle('bom:patch', async (_event, params: unknown) => {
    const p         = params as Record<string, unknown>
    const safeBom   = validateFilePath(p['bomPath'])
    const safePatch = validateFilePath(p['patchPath'])

    const args = [
      'patch',
      '--input-file', safeBom,
      '--patch-file', safePatch,
      '--config-schema',  configPath,
      '--config-license', licensePolicyPath,
    ]
    console.log('[bom:patch] binary:', binaryPath)
    console.log('[bom:patch] args:', args)
    const res = await runBinary(binaryPath, args, baseEnv)
    console.log('[bom:patch] code:', res.code)
    console.log('[bom:patch] stdout (first 120):', res.stdout.slice(0, 120))
    console.log('[bom:patch] stderr (first 120):', res.stderr.slice(0, 120))
    return { stdout: res.stdout, stderr: res.stderr, code: res.code }
  })
}
