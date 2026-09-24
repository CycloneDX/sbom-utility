#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
SERVER_BIN="$ROOT_DIR/sbom-utility"
PORT="8787"

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}

trap cleanup EXIT INT TERM

if [[ ! -x "$SERVER_BIN" ]]; then
  echo "Missing executable: $SERVER_BIN" >&2
  echo "Build it first with: make build" >&2
  exit 1
fi

EXISTING_PID="$(lsof -t -iTCP:${PORT} -sTCP:LISTEN 2>/dev/null | head -n 1 || true)"
if [[ -n "$EXISTING_PID" ]]; then
  EXISTING_CMD="$(ps -p "$EXISTING_PID" -o command= 2>/dev/null || true)"
  if [[ "$EXISTING_CMD" == *"sbom-utility serve"* ]]; then
    kill "$EXISTING_PID" 2>/dev/null || true
    for _ in {1..25}; do
      if ! lsof -t -iTCP:${PORT} -sTCP:LISTEN >/dev/null 2>&1; then
        break
      fi
      sleep 0.2
    done
  else
    echo "Port ${PORT} already in use by PID ${EXISTING_PID}. Stop it first and retry." >&2
    exit 1
  fi
fi

"$SERVER_BIN" serve --port "$PORT" &
SERVER_PID=$!

for _ in {1..50}; do
  if lsof -t -iTCP:${PORT} -sTCP:LISTEN >/dev/null 2>&1; then
    exec npm run dev:browser
  fi
  sleep 0.2
done

echo "Timed out waiting for sbom-utility serve on port ${PORT}." >&2
exit 1
