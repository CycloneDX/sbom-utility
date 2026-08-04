# SPDX-License-Identifier: Apache-2.0
# =============================================================================
# install.ps1 — SBOM Utility Electron GUI installer for Windows (PowerShell)
#
# What this script does:
#   1. Verifies system prerequisites (Node.js >= 20, npm)
#   2. Checks that sbom-utility.exe exists in the repo root
#   3. Runs `npm ci` in gui-ts/ to install exact locked dependencies
#   4. (Optional -Dist) builds the production Electron app for Windows
#
# Usage (run from repo root, NOT from inside gui-ts/):
#   .\gui-ts\install.ps1              # install deps only
#   .\gui-ts\install.ps1 -Dist        # install deps + build installer
#
# Execution policy — if you get a policy error, run once as Admin:
#   Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
# =============================================================================
param(
    [switch]$Dist,
    [switch]$Help
)

if ($Help) {
    Get-Content $MyInvocation.MyCommand.Path | Select-String "^#" | ForEach-Object { $_.Line -replace '^# ?','' }
    exit 0
}

$ErrorActionPreference = 'Stop'
$REPO_ROOT = Resolve-Path (Join-Path $PSScriptRoot '..')
$GUI_DIR   = Join-Path $REPO_ROOT 'gui-ts'

function Info  { param($m) Write-Host "[info]  $m" -ForegroundColor Cyan }
function Ok    { param($m) Write-Host "[ ok ]  $m" -ForegroundColor Green }
function Warn  { param($m) Write-Host "[warn]  $m" -ForegroundColor Yellow }
function Fail  { param($m) Write-Host "[err]   $m" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "  SBOM Utility — Electron GUI Installer" -ForegroundColor White
Write-Host "  ────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host ""

# ── 1. Node.js prerequisite check ─────────────────────────────────────────────
Info "Checking Node.js..."
$nodeCmd = Get-Command node -ErrorAction SilentlyContinue
if (-not $nodeCmd) {
    Fail "Node.js not found. Download and install from https://nodejs.org (LTS recommended)."
}
$nodeVer = (node --version).TrimStart('v')
$nodeMajor = [int]($nodeVer.Split('.')[0])
if ($nodeMajor -lt 20) {
    Fail "Node.js $nodeVer is too old. Electron 31 requires Node.js >= 20."
}
Ok "Node.js $nodeVer"

Info "Checking npm..."
$npmCmd = Get-Command npm -ErrorAction SilentlyContinue
if (-not $npmCmd) { Fail "npm not found. Reinstall Node.js from https://nodejs.org." }
Ok "npm $(npm --version)"

# ── 2. sbom-utility binary check ──────────────────────────────────────────────
Info "Checking sbom-utility.exe..."
$binary = Join-Path $REPO_ROOT 'sbom-utility.exe'
if (-not (Test-Path $binary)) {
    Warn "sbom-utility.exe not found at $binary"
    Warn "Build it first:  go build -o sbom-utility.exe ."
    Warn "The GUI will not function until the binary is present."
} else {
    Ok "sbom-utility.exe found at $binary"
}

# ── 3. npm ci ─────────────────────────────────────────────────────────────────
Info "Installing npm dependencies (npm ci)..."
Push-Location $GUI_DIR
try {
    npm ci
    if ($LASTEXITCODE -ne 0) { Fail "npm ci failed (exit code $LASTEXITCODE)." }
    Ok "Dependencies installed."

    # ── 4. Optional build ─────────────────────────────────────────────────────
    if ($Dist) {
        Info "Building distributable (npm run dist)..."
        npm run "dist:win"
        if ($LASTEXITCODE -ne 0) { Fail "npm run dist:win failed." }
        Ok "Installer written to gui-ts\dist-release\"
    } else {
        Write-Host ""
        Write-Host "  Done. To run in development mode:"
        Write-Host "    cd gui-ts; npm run dev"
        Write-Host ""
        Write-Host "  To build a distributable installer:"
        Write-Host "    cd gui-ts; npm run dist:win"
        Write-Host "  Or re-run this script with -Dist:"
        Write-Host "    .\gui-ts\install.ps1 -Dist"
    }
} finally {
    Pop-Location
}

Write-Host ""
