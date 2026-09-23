#!/usr/bin/env bash
# Start agent-gateway local stack (Decision + Envoy + echo + hbone-ingress)
# in place of the egresstunnel mock Envoy. E2B EGRESS_GATEWAY_ADDR stays :15008.
set -euo pipefail
# shellcheck source=common.sh
. "$(cd "$(dirname "$0")" && pwd)/common.sh"

GW_ROOT="${AGENT_GATEWAY_ROOT:-$RUNTIME_DIR/../agent-gateway}"
[ -d "$GW_ROOT" ] || die "agent-gateway not found at $GW_ROOT (set AGENT_GATEWAY_ROOT)"

need_cmd curl
"$GW_ROOT/scripts/e2e-e2b-up.sh"

# Keep host egress certs in sync for the nsenter'd orchestrator (tunnel CA only;
# server trust is still gateway-ca from the mock cert dir copied earlier).
CERT_SRC="$MOCK_DIR/certs"
sudo_cmd mkdir -p "$CERT_DST"
sudo_cmd cp -f \
  "$CERT_SRC/tunnel-ca.crt" \
  "$CERT_SRC/tunnel-ca.key" \
  "$CERT_SRC/gateway-ca.crt" \
  "$CERT_DST/"
sudo_cmd chmod 644 "$CERT_DST"/*

log "agent-gateway HBONE front ready on 127.0.0.1:15008"
