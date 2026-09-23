#!/usr/bin/env bash
# Full control-plane e2e:
#   POST template build (SDK → /v3/templates + start build)
#   POST /sandboxes with iam.tokens
#   guest curl through tcpfirewall → HBONE CONNECT+mTLS → mock Envoy → capture
#
# Requires: embed compose up, mock Envoy up, live orchestrator with EGRESS_* and
# an HBONE-capable binary (see install-hbone-orchestrator.sh).
#
# Env:
#   TEMPLATE_ALIAS   default hbone-e2e
#   FORCE_REBUILD=1  rebuild the alias even if a ready template exists
#   KEEP_SANDBOX=1   do not DELETE the sandbox at the end
#   E2B_API_KEY      otherwise read from the seed-state volume
set -euo pipefail
# shellcheck source=common.sh
. "$(cd "$(dirname "$0")" && pwd)/common.sh"

need_cmd docker
need_cmd curl
need_cmd python3

API_KEY="$(team_api_key)"
[ -n "$API_KEY" ] || die "empty API key"
NODE_IMG="$(node_e2b_image)"
ALIAS="${TEMPLATE_ALIAS:-hbone-e2e}"
MARKER="hbone-api-e2e-$(date +%s)"
GUEST_PATH="/hbone-api-e2e"
GUEST_HOST="api.example.com"

curl -sf --max-time 3 "$API_URL/health" >/dev/null || die "api not healthy at $API_URL"
curl -sf --max-time 3 http://127.0.0.1:5008/health >/dev/null || die "orchestrator not healthy"
curl -sf --max-time 3 -X POST http://127.0.0.1:18080/hbone-probe -d probe >/dev/null \
  || die "mock capture not answering on :18080"

log "building/reusing template alias=$ALIAS via API"
TPL_JSON="$(docker run --rm --network host \
  -e E2B_API_URL="$API_URL" \
  -e E2B_API_KEY="$API_KEY" \
  -e TEMPLATE_ALIAS="$ALIAS" \
  -e FORCE_REBUILD="${FORCE_REBUILD:-0}" \
  -v "$E2E_DIR/build-template.mjs:/app/build-template.mjs:ro" \
  "$NODE_IMG" node /app/build-template.mjs)"
log "template result: $TPL_JSON"
TEMPLATE_ID="$(printf '%s\n' "$TPL_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["templateID"])')"
[ -n "$TEMPLATE_ID" ] || die "no templateID"

log "POST /sandboxes templateID=$TEMPLATE_ID iam.tokens.default JWT-SVID"
CREATE_BODY="$(python3 - <<PY
import json
print(json.dumps({
  "templateID": "$ALIAS",
  "timeout": 300,
  "iam": {
    "tokens": {
      "default": {
        "audience": "egress-e2e",
        "tokenType": "JWT-SVID"
      }
    }
  },
  "metadata": {"purpose": "hbone-api-e2e"}
}))
PY
)"
CREATE="$(curl -sS -w '\n%{http_code}' -X POST "$API_URL/sandboxes" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d "$CREATE_BODY")"
HTTP_CODE="$(printf '%s\n' "$CREATE" | tail -1)"
BODY="$(printf '%s\n' "$CREATE" | sed '$d')"
[ "$HTTP_CODE" = "201" ] || die "sandbox create HTTP $HTTP_CODE: $BODY"
SBX_ID="$(printf '%s\n' "$BODY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["sandboxID"])')"
log "sandbox $SBX_ID created"

cleanup() {
  if [ "${KEEP_SANDBOX:-0}" = "1" ]; then
    log "KEEP_SANDBOX=1; leaving $SBX_ID"
    return
  fi
  curl -sS -o /dev/null -X DELETE "$API_URL/sandboxes/$SBX_ID" -H "X-API-Key: $API_KEY" || true
  log "deleted sandbox $SBX_ID"
}
trap cleanup EXIT

log "guest curl through HBONE (sandboxUrl=$SANDBOX_URL)"
GUEST_JSON="$(docker run --rm --network host \
  -e E2B_API_URL="$API_URL" \
  -e E2B_API_KEY="$API_KEY" \
  -e E2B_SANDBOX_URL="$SANDBOX_URL" \
  -e SANDBOX_ID="$SBX_ID" \
  -e MARKER="$MARKER" \
  -e GUEST_PATH="$GUEST_PATH" \
  -e GUEST_HOST="$GUEST_HOST" \
  -e GUEST_METHOD=POST \
  -v "$E2E_DIR/guest-egress.mjs:/app/guest-egress.mjs:ro" \
  "$NODE_IMG" node /app/guest-egress.mjs)"
log "guest: $GUEST_JSON"
printf '%s\n' "$GUEST_JSON" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert "ok: request captured" in d.get("stdout",""), d'

CAP_LOGS="$(wait_mock_log capture "$MARKER")"
ENV_LOGS="$(wait_mock_log envoy "sbx/${SBX_ID}/exec/")"

printf '%s\n' "$CAP_LOGS" | grep -q "POST $GUEST_PATH" || die "capture missing POST $GUEST_PATH"
printf '%s\n' "$CAP_LOGS" | grep -q "Host: $GUEST_HOST" || die "capture missing Host: $GUEST_HOST"

SPIFFE="$(printf '%s\n' "$ENV_LOGS" | python3 -c "
import json, sys
sbx = '$SBX_ID'
want_auth = '${GUEST_HOST}:80'
for line in sys.stdin:
    i = line.find('{')
    if i < 0:
        continue
    try:
        o = json.loads(line[i:])
    except Exception:
        continue
    san = o.get('peer_uri_san') or ''
    if sbx not in san:
        continue
    if o.get('method') != 'CONNECT':
        sys.exit('envoy line for sandbox is not CONNECT: ' + line.strip())
    if o.get('authority') != want_auth:
        sys.exit('envoy authority %r want %r' % (o.get('authority'), want_auth))
    print(san)
    break
else:
    sys.exit('no hbone_connect JSON for sandbox')
")"
[ -n "$SPIFFE" ] || die "could not parse peer_uri_san"

log "pass"
log "  template=$ALIAS ($TEMPLATE_ID)"
log "  sandbox=$SBX_ID"
log "  spiffe=$SPIFFE"
log "  capture POST $GUEST_PATH marker=$MARKER"
