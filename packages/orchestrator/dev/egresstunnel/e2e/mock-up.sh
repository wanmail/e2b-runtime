#!/usr/bin/env bash
# Start mock Envoy+capture and copy tunnel/gateway certs onto the host path
# the nsenter'd orchestrator reads (compose mounts do not follow nsenter -t 1).
set -euo pipefail
# shellcheck source=common.sh
. "$(cd "$(dirname "$0")" && pwd)/common.sh"

need_cmd docker
need_cmd curl

if [ ! -f "$MOCK_DIR/certs/tunnel-ca.crt" ] || [ ! -f "$MOCK_DIR/certs/gateway.crt" ]; then
  log "generating mock certs"
  "$MOCK_DIR/certs/gen.sh"
fi

log "starting mock Envoy on :15008"
if [ "${BUILD_MOCK:-0}" = "1" ]; then
  compose_mock up --build -d
else
  compose_mock up -d
fi
wait_http "http://127.0.0.1:18080/" 30 || true
# capture answers 200 with a body even without a path
curl -sf --max-time 3 -X POST http://127.0.0.1:18080/hbone-probe -d probe >/dev/null \
  || die "capture HTTP on :18080 is not answering"

log "installing certs at $CERT_DST (host paths used by orchestrator)"
sudo_cmd mkdir -p "$CERT_DST"
sudo_cmd cp -f \
  "$MOCK_DIR/certs/tunnel-ca.crt" \
  "$MOCK_DIR/certs/tunnel-ca.key" \
  "$MOCK_DIR/certs/gateway-ca.crt" \
  "$CERT_DST/"
sudo_cmd chmod 644 "$CERT_DST/tunnel-ca.crt" "$CERT_DST/gateway-ca.crt" "$CERT_DST/tunnel-ca.key"

log "mock ready (envoy :15008, capture :18080, certs $CERT_DST)"
