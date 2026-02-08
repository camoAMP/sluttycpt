#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT="${PORT:-5173}"
HOST="${HOST:-0.0.0.0}"
TUNNEL_NAME="${TUNNEL_NAME:-camodick}"

mkdir -p videos

SERVER_PID=""
TUNNEL_PID=""
STARTED_SERVER=0
STARTED_TUNNEL=0

SERVER_BASE="http://127.0.0.1:${PORT}"

is_port_listening() {
  if command -v ss >/dev/null 2>&1; then
    ss -ltnH sport = :"${PORT}" 2>/dev/null | grep -q .
    return $?
  fi
  if command -v lsof >/dev/null 2>&1; then
    lsof -iTCP:"${PORT}" -sTCP:LISTEN -n -P >/dev/null 2>&1
    return $?
  fi
  if command -v netstat >/dev/null 2>&1; then
    netstat -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(:|\\.)${PORT}$"
    return $?
  fi

  # Fallback: bash TCP connect probe
  (echo >/dev/tcp/127.0.0.1/"${PORT}") >/dev/null 2>&1
}

is_camodick_server() {
  curl -fsS --max-time 1 "${SERVER_BASE}/api/info" 2>/dev/null | grep -q '"mode": "server"'
}

if is_camodick_server; then
  echo "[camodick] server already running at ${SERVER_BASE}"
else
  if is_port_listening; then
    echo "[camodick] ERROR: port ${PORT} is already in use, but ${SERVER_BASE}/api/info is not responding as camodick." >&2
    echo "[camodick] Stop the process using port ${PORT}, or run with a different port:" >&2
    echo "[camodick]   PORT=5174 bash scripts/run-public.sh" >&2
    exit 1
  fi

  echo "[camodick] starting server on ${HOST}:${PORT} ..."
  HOST="$HOST" PORT="$PORT" node server.js &
  SERVER_PID="$!"
  STARTED_SERVER=1

  # Wait briefly for the server to accept requests.
  for _ in {1..40}; do
    if is_camodick_server; then break; fi
    sleep 0.2
  done

  if ! is_camodick_server; then
    echo "[camodick] ERROR: server did not start or is not responding at ${SERVER_BASE}/api/info" >&2
    exit 1
  fi
fi

CLOUDFLARED="${CLOUDFLARED_BIN:-}"
if [[ -z "${CLOUDFLARED}" && -x "$ROOT/cloudflared" ]]; then
  CLOUDFLARED="$ROOT/cloudflared"
fi
if [[ -z "${CLOUDFLARED}" ]]; then
  CLOUDFLARED="$(command -v cloudflared || true)"
fi

if [[ -n "${CLOUDFLARED}" ]]; then
  if command -v pgrep >/dev/null 2>&1 && pgrep -f "cloudflared tunnel run.*\\b${TUNNEL_NAME}\\b" >/dev/null 2>&1; then
    echo "[camodick] cloudflared tunnel '${TUNNEL_NAME}' already running"
  else
    echo "[camodick] starting cloudflared tunnel '${TUNNEL_NAME}' -> ${SERVER_BASE} ..."
    "${CLOUDFLARED}" tunnel run --url "${SERVER_BASE}" "${TUNNEL_NAME}" &
    TUNNEL_PID="$!"
    STARTED_TUNNEL=1
  fi
else
  echo "[camodick] cloudflared not found; tunnel not started (LAN-only)." >&2
fi

cleanup() {
  if [[ "${STARTED_SERVER}" == "1" || "${STARTED_TUNNEL}" == "1" ]]; then
    echo "[camodick] stopping..."
  fi
  if [[ "${STARTED_SERVER}" == "1" && -n "${SERVER_PID}" ]]; then
    kill "${SERVER_PID}" 2>/dev/null || true
  fi
  if [[ "${STARTED_TUNNEL}" == "1" && -n "${TUNNEL_PID}" ]]; then
    kill "${TUNNEL_PID}" 2>/dev/null || true
  fi
}
trap cleanup INT TERM EXIT

if [[ -n "${TUNNEL_PID}" && -n "${SERVER_PID}" ]]; then
  wait -n "${SERVER_PID}" "${TUNNEL_PID}"
elif [[ -n "${TUNNEL_PID}" ]]; then
  wait "${TUNNEL_PID}"
elif [[ -n "${SERVER_PID}" ]]; then
  wait "${SERVER_PID}"
else
  # Nothing started (both were already running). Exit successfully.
  exit 0
fi
