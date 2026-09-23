#!/usr/bin/env bash
# Bring up mock Envoy, install the HBONE orchestrator, then run the API e2e.
# SKIP_INSTALL=1  mock-up + api-e2e only (orchestrator already wired)
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=common.sh
. "$DIR/common.sh"

if [ "${SKIP_INSTALL:-0}" = "1" ]; then
  "$DIR/mock-up.sh"
else
  "$DIR/install-hbone-orchestrator.sh"
fi
"$DIR/api-e2e.sh"
