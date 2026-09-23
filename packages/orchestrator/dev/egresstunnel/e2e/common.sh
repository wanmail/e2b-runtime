#!/usr/bin/env bash
# Shared paths and helpers for HBONE e2e scripts. Source, do not execute.
set -euo pipefail

E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOCK_DIR="$(cd "$E2E_DIR/.." && pwd)"
ORCH_DIR="$(cd "$MOCK_DIR/../.." && pwd)"
RUNTIME_DIR="$(cd "$ORCH_DIR/../.." && pwd)"
COMPOSE_DIR="${COMPOSE_DIR:-$RUNTIME_DIR/embed/compose}"

CERT_DST="${CERT_DST:-/var/lib/e2b/egress-certs}"
ORCH_BIN="${ORCH_BIN:-/var/lib/e2b/bin/orchestrator}"
API_URL="${E2B_API_URL:-http://127.0.0.1:3000}"
SANDBOX_URL="${E2B_SANDBOX_URL:-http://127.0.0.1:3002}"

log() { printf 'hbone-e2e: %s\n' "$*"; }
die() { printf 'hbone-e2e: %s\n' "$*" >&2; exit 1; }

need_cmd() {
  command -v "$1" >/dev/null || die "missing $1"
}

node_e2b_image() {
  local line
  line="$(grep -E '^E2B_NODE_E2B_IMAGE=' "$COMPOSE_DIR/.env" | head -1)"
  [ -n "$line" ] || die "E2B_NODE_E2B_IMAGE not in $COMPOSE_DIR/.env"
  # drop comments after the image pin
  printf '%s\n' "${line#E2B_NODE_E2B_IMAGE=}" | awk '{print $1}'
}

# Team API key for this embed install (seed volume / ready container).
team_api_key() {
  if [ -n "${E2B_API_KEY:-}" ]; then
    printf '%s\n' "$E2B_API_KEY"
    return
  fi
  docker volume inspect e2b_seed-state >/dev/null 2>&1 || die "no e2b_seed-state volume; is embed compose up?"
  docker run --rm -v e2b_seed-state:/run/e2b:ro alpine cat /run/e2b/team-api-key
}

compose_embed() {
  docker compose -f "$COMPOSE_DIR/compose.yaml" --project-directory "$COMPOSE_DIR" "$@"
}

compose_mock() {
  docker compose -f "$MOCK_DIR/docker-compose.yml" --project-directory "$MOCK_DIR" "$@"
}

wait_http() {
  local url="$1" tries="${2:-60}"
  local i
  for i in $(seq 1 "$tries"); do
    if curl -sf --max-time 2 "$url" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  die "timeout waiting for $url"
}

# Envoy access logs flush after the CONNECT stream ends (often DR). Poll.
wait_mock_log() {
  local service="$1" needle="$2" tries="${3:-40}"
  local i out
  for i in $(seq 1 "$tries"); do
    out="$(compose_mock logs "$service" 2>&1 || true)"
    if printf '%s\n' "$out" | grep -q -- "$needle"; then
      printf '%s\n' "$out"
      return 0
    fi
    sleep 0.25
  done
  die "timeout waiting for $service logs to contain: $needle"
}

sudo_cmd() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  else
    sudo -n "$@"
  fi
}
