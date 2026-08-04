#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# =============================================================================
# install.sh — SBOM Utility Electron GUI installer for macOS and Linux
#
# What this script does:
#   1. Verifies system prerequisites (Node.js ≥ 20, npm)
#   2. Checks that the sbom-utility CLI binary exists in the repo root
#   3. Runs `npm ci` in gui-ts/ to install exact locked dependencies
#   4. (Optional) builds the production Electron app for the current platform
#
# Usage:
#   ./gui-ts/install.sh          # install deps only (for development)
#   ./gui-ts/install.sh --dist   # install deps + build distributable
#   ./gui-ts/install.sh --help
#
# Run from the repo root, NOT from inside gui-ts/.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
GUI_DIR="${REPO_ROOT}/gui-ts"

RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
CYN='\033[0;36m'
RST='\033[0m'

info()  { echo -e "${CYN}[info]${RST}  $*"; }
ok()    { echo -e "${GRN}[ ok ]${RST}  $*"; }
warn()  { echo -e "${YLW}[warn]${RST}  $*"; }
error() { echo -e "${RED}[err] ${RST}  $*" >&2; }
die()   { error "$*"; exit 1; }

# ── Parse args ────────────────────────────────────────────────────────────────
BUILD_DIST=false
for arg in "$@"; do
  case "$arg" in
    --dist)   BUILD_DIST=true ;;
    --help|-h)
      sed -n '3,/^# ===/p' "$0" | grep '^#' | sed 's/^# \?//'
      exit 0
      ;;
    *) die "Unknown argument: $arg" ;;
  esac
done

echo ""
echo "  SBOM Utility — Electron GUI Installer"
echo "  ────────────────────────────────────────"
echo ""

# ── 1. Node.js prerequisite check ────────────────────────────────────────────
info "Checking Node.js…"
if ! command -v node &>/dev/null; then
  die "Node.js not found. Install Node.js ≥ 20 from https://nodejs.org (LTS recommended)."
fi
NODE_VER=$(node --version | sed 's/v//')
NODE_MAJOR=$(echo "$NODE_VER" | cut -d. -f1)
if [[ "$NODE_MAJOR" -lt 20 ]]; then
  die "Node.js ${NODE_VER} is too old. Electron 31 requires Node.js ≥ 20."
fi
ok "Node.js ${NODE_VER}"

info "Checking npm…"
if ! command -v npm &>/dev/null; then
  die "npm not found. It ships with Node.js — reinstall Node.js."
fi
ok "npm $(npm --version)"

# ── 2. sbom-utility binary check ─────────────────────────────────────────────
info "Checking sbom-utility CLI binary…"
BINARY="${REPO_ROOT}/sbom-utility"
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]]; then
  BINARY="${BINARY}.exe"
fi
if [[ ! -x "$BINARY" ]]; then
  warn "sbom-utility binary not found at ${BINARY}"
  warn "Build it first with:  go build -o sbom-utility ."
  warn "The Electron GUI will not function until the binary is present."
else
  ok "sbom-utility found at ${BINARY}"
fi

# ── 3. npm ci (clean install from package-lock.json) ─────────────────────────
info "Installing npm dependencies (npm ci)…"
cd "${GUI_DIR}"
npm ci
ok "Dependencies installed."

# ── 4. Optional: build distributable ─────────────────────────────────────────
if [[ "$BUILD_DIST" == true ]]; then
  info "Building distributable (npm run dist)…"
  npm run dist
  ok "Distribution package(s) written to gui-ts/dist-release/"
else
  echo ""
  echo "  Done. To run in development mode:"
  echo "    cd gui-ts && npm run dev"
  echo ""
  echo "  To build a distributable package:"
  echo "    cd gui-ts && npm run dist"
  echo "  Or re-run this script with --dist:"
  echo "    ./gui-ts/install.sh --dist"
fi

echo ""
