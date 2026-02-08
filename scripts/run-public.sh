#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT="${PORT:-5173}"
HOST="${HOST:-0.0.0.0}"
TUNNEL_NAME="${TUNNEL_NAME:-camodick}"

mkdir -p videos

echo "[camodick] starting server on ${HOST}:${PORT} ..."
HOST="$HOST" PORT="$PORT" node server.js &
SERVER_PID="$!"

CLOUDFLARED="${CLOUDFLARED_BIN:-}"
if [[ -z "${CLOUDFLARED}" && -x "$ROOT/cloudflared" ]]; then
  CLOUDFLARED="$ROOT/cloudflared"
fi
if [[ -z "${CLOUDFLARED}" ]]; then
  CLOUDFLARED="$(command -v cloudflared || true)"
fi

TUNNEL_PID=""
if [[ -n "${CLOUDFLARED}" ]]; then
  echo "[camodick] starting cloudflared tunnel '${TUNNEL_NAME}' ..."
  "${CLOUDFLARED}" tunnel run "${TUNNEL_NAME}" &
  TUNNEL_PID="$!"
else
  echo "[camodick] cloudflared not found; tunnel not started (LAN-only)." >&2
fi

cleanup() {
  echo "[camodick] stopping..."
  kill "${SERVER_PID}" 2>/dev/null || true
  if [[ -n "${TUNNEL_PID}" ]]; then
    kill "${TUNNEL_PID}" 2>/dev/null || true
  fi
}
trap cleanup INT TERM EXIT

if [[ -n "${TUNNEL_PID}" ]]; then
  wait -n "${SERVER_PID}" "${TUNNEL_PID}"
else
  wait "${SERVER_PID}"
fi

