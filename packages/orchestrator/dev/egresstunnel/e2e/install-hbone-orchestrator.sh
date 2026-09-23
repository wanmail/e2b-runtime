#!/usr/bin/env bash
# Build the HBONE orchestrator, install it over /var/lib/e2b/bin/orchestrator,
# and recreate the embed compose orchestrator with EGRESS_* from compose.override.yaml.
#
# SKIP_BUILD=1  reuse the binary already at /tmp/orchestrator-hbone or ORCH_BIN
# SKIP_RECREATE=1  copy binary/certs only
set -euo pipefail
# shellcheck source=common.sh
. "$(cd "$(dirname "$0")" && pwd)/common.sh"

need_cmd docker
need_cmd curl
need_cmd go

OVERRIDE="$COMPOSE_DIR/compose.override.yaml"
[ -f "$OVERRIDE" ] || die "missing $OVERRIDE (EGRESS_* for the live orchestrator)"

"$E2E_DIR/mock-up.sh"

STAGED="${STAGED_ORCH_BIN:-/tmp/orchestrator-hbone}"

if [ "${SKIP_BUILD:-0}" != "1" ]; then
  log "building orchestrator with CGO (HBONE + Firecracker)"
  (
    cd "$ORCH_DIR"
    export CGO_ENABLED=1
    export GOMODCACHE="${GOMODCACHE:-/tmp/gomodcache}"
    export GOCACHE="${GOCACHE:-/tmp/gocache}"
    go build -o "$STAGED" .
  )
else
  [ -x "$STAGED" ] || die "SKIP_BUILD=1 but $STAGED is missing"
fi

log "stopping orchestrator so $ORCH_BIN is not busy"
compose_embed stop orchestrator

if [ -x "$ORCH_BIN" ]; then
  sudo_cmd cp -a "$ORCH_BIN" "${ORCH_BIN}.pre-hbone" || true
fi
sudo_cmd cp "$STAGED" "$ORCH_BIN"
sudo_cmd chmod 755 "$ORCH_BIN"

if [ "${SKIP_RECREATE:-0}" = "1" ]; then
  log "SKIP_RECREATE=1; start orchestrator yourself"
  exit 0
fi

log "recreating orchestrator with $OVERRIDE"
(
  cd "$COMPOSE_DIR"
  docker compose up -d --force-recreate --no-deps orchestrator
)
wait_http "http://127.0.0.1:5008/health" 90

# Confirm the live process got EGRESS_GATEWAY_ADDR (nsenter host pid).
pid="$(pgrep -af '/var/lib/e2b/bin/orchestrator' | grep -v grep | awk '{print $1}' | head -1 || true)"
[ -n "$pid" ] || die "orchestrator pid not found"
if ! sudo_cmd tr '\0' '\n' < "/proc/$pid/environ" | grep -q '^EGRESS_GATEWAY_ADDR='; then
  die "orchestrator pid $pid has no EGRESS_GATEWAY_ADDR (is compose.override.yaml applied?)"
fi
log "orchestrator pid $pid healthy with EGRESS_* (gateway 127.0.0.1:15008)"
