#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT="${PORT:-5173}"
HOST="${HOST:-0.0.0.0}"
TUNNEL_NAME="${TUNNEL_NAME:-camodick}"
# Optional: run a tunnel from a Cloudflare dashboard token, without needing `cloudflared tunnel login`.
# Prefer token-file to keep the token out of `ps` output.
TUNNEL_TOKEN="${TUNNEL_TOKEN:-}"
TUNNEL_TOKEN_FILE="${TUNNEL_TOKEN_FILE:-}"
if [[ -n "${TUNNEL_TOKEN}" && -z "${TUNNEL_TOKEN_FILE}" ]]; then
  TUNNEL_TOKEN_FILE="$ROOT/.camfordick-data/tunnel-token.txt"
fi

mkdir -p videos
mkdir -p .camfordick-data

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

  # /proc fallback: detect listeners even if the port is bound to a non-loopback IP.
  # Works on Linux without extra tools.
  local port_hex
  port_hex="$(printf '%04X' "${PORT}")"
  if [[ -r /proc/net/tcp ]]; then
    if awk -v p=":${port_hex}" 'NR>1 && $4=="0A" && $2 ~ p { found=1; exit } END { exit(found?0:1) }' /proc/net/tcp; then
      return 0
    fi
  fi
  if [[ -r /proc/net/tcp6 ]]; then
    if awk -v p=":${port_hex}" 'NR>1 && $4=="0A" && $2 ~ p { found=1; exit } END { exit(found?0:1) }' /proc/net/tcp6; then
      return 0
    fi
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

SKIP_TUNNEL=0
# If the user has already installed and enabled cloudflared via systemd, don't start a second tunnel.
if command -v systemctl >/dev/null 2>&1; then
  if systemctl is-active --quiet cloudflared.service 2>/dev/null; then
    echo "[camodick] cloudflared.service already running (systemd); skipping tunnel start."
    SKIP_TUNNEL=1
  fi
fi

if [[ "${SKIP_TUNNEL}" == "0" && -n "${CLOUDFLARED}" ]]; then
  if [[ -n "${TUNNEL_TOKEN_FILE}" ]]; then
    if [[ -n "${TUNNEL_TOKEN}" ]]; then
      # 0600 token file (best-effort) so the secret isn't exposed via process args.
      umask 177
      printf "%s" "${TUNNEL_TOKEN}" >"${TUNNEL_TOKEN_FILE}"
      chmod 600 "${TUNNEL_TOKEN_FILE}" 2>/dev/null || true
    fi

    if [[ ! -s "${TUNNEL_TOKEN_FILE}" ]]; then
      echo "[camodick] ERROR: TUNNEL_TOKEN_FILE is set but the file is missing/empty: ${TUNNEL_TOKEN_FILE}" >&2
      echo "[camodick] Provide the token via env var, for example:" >&2
      echo "[camodick]   TUNNEL_TOKEN='...' bash scripts/run-public.sh" >&2
      exit 1
    fi

    if command -v pgrep >/dev/null 2>&1 && pgrep -f "${TUNNEL_TOKEN_FILE}" >/dev/null 2>&1; then
      echo "[camodick] cloudflared tunnel (token-file) already running"
    else
      echo "[camodick] starting cloudflared tunnel (token-file) -> ${SERVER_BASE} ..."
      "${CLOUDFLARED}" tunnel run --token-file "${TUNNEL_TOKEN_FILE}" --url "${SERVER_BASE}" &
      TUNNEL_PID="$!"
      STARTED_TUNNEL=1
    fi
  else
    if command -v pgrep >/dev/null 2>&1 && pgrep -f "cloudflared tunnel run.*\\b${TUNNEL_NAME}\\b" >/dev/null 2>&1; then
      echo "[camodick] cloudflared tunnel '${TUNNEL_NAME}' already running"
    else
      echo "[camodick] starting cloudflared tunnel '${TUNNEL_NAME}' -> ${SERVER_BASE} ..."
      "${CLOUDFLARED}" tunnel run --url "${SERVER_BASE}" "${TUNNEL_NAME}" &
      TUNNEL_PID="$!"
      STARTED_TUNNEL=1
    fi
  fi
elif [[ "${SKIP_TUNNEL}" == "0" ]]; then
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
