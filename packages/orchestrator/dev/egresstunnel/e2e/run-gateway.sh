#!/usr/bin/env bash
# Full path: agent-gateway local + E2B API sandbox → HBONE → injected credentials.
#
#   SKIP_INSTALL=1     orchestrator already has HBONE binary + EGRESS_*
#   SKIP_GATEWAY=1     Decision/Envoy/hbone-ingress already up
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=common.sh
. "$DIR/common.sh"

if [ "${SKIP_INSTALL:-0}" != "1" ]; then
  "$DIR/install-hbone-orchestrator.sh"
fi
if [ "${SKIP_GATEWAY:-0}" != "1" ]; then
  "$DIR/gateway-up.sh"
else
  "$DIR/mock-up.sh" 2>/dev/null || true
fi
"$DIR/api-gateway-e2e.sh"
