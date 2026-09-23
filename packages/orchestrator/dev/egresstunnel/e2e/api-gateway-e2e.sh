#!/usr/bin/env bash
# API e2e against agent-gateway (not the capture mock):
#   POST template + POST /sandboxes iam.tokens
#   PUT gateway binding for the live sandbox id
#   guest curl Host: api.github.com → HBONE → hbone-ingress → Envoy → echo
#   assert echoed Authorization: Bearer ghs_mock (connector injection)
#
# Prerequisites: embed compose, HBONE orchestrator, ./gateway-up.sh
set -euo pipefail
# shellcheck source=common.sh
. "$(cd "$(dirname "$0")" && pwd)/common.sh"

need_cmd docker
need_cmd curl
need_cmd python3

GW_ROOT="${AGENT_GATEWAY_ROOT:-$RUNTIME_DIR/../agent-gateway}"
API_KEY="$(team_api_key)"
NODE_IMG="$(node_e2b_image)"
ALIAS="${TEMPLATE_ALIAS:-hbone-e2e}"
GUEST_HOST="${GUEST_HOST:-api.github.com}"
GUEST_PATH="${GUEST_PATH:-/}"
GUEST_DEST="${GUEST_DEST:-http://203.0.113.80}"
WANT_AUTH="${WANT_AUTH:-Bearer ghs_mock}"

curl -sf --max-time 3 "$API_URL/health" >/dev/null || die "api not healthy"
curl -sf --max-time 3 http://127.0.0.1:5008/health >/dev/null || die "orchestrator not healthy"
curl -sf --max-time 3 http://127.0.0.1:9002/healthz >/dev/null || die "agent-gateway Decision not up (run ./gateway-up.sh)"
curl -sf --max-time 3 http://127.0.0.1:19901/ready >/dev/null || die "agent-gateway Envoy not ready"
ss -ltn | grep -q ':15008' || die "hbone-ingress not listening on :15008"

log "building/reusing template alias=$ALIAS"
TPL_JSON="$(docker run --rm --network host \
  -e E2B_API_URL="$API_URL" \
  -e E2B_API_KEY="$API_KEY" \
  -e TEMPLATE_ALIAS="$ALIAS" \
  -e FORCE_REBUILD="${FORCE_REBUILD:-0}" \
  -v "$E2E_DIR/build-template.mjs:/app/build-template.mjs:ro" \
  "$NODE_IMG" node /app/build-template.mjs)"
log "template: $TPL_JSON"
TEMPLATE_ID="$(printf '%s\n' "$TPL_JSON" | python3 -c 'import json,sys; print(json.load(sys.stdin)["templateID"])')"

log "POST /sandboxes with iam.tokens"
CREATE_BODY="$(python3 - <<PY
import json
print(json.dumps({
  "templateID": "$ALIAS",
  "timeout": 300,
  "iam": {"tokens": {"default": {"audience": "egress-e2e", "tokenType": "JWT-SVID"}}},
  "metadata": {"purpose": "hbone-agent-gateway-e2e"}
}))
PY
)"
CREATE="$(curl -sS -w '\n%{http_code}' -X POST "$API_URL/sandboxes" \
  -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" -d "$CREATE_BODY")"
HTTP_CODE="$(printf '%s\n' "$CREATE" | tail -1)"
BODY="$(printf '%s\n' "$CREATE" | sed '$d')"
[ "$HTTP_CODE" = "201" ] || die "sandbox create HTTP $HTTP_CODE: $BODY"
SBX_ID="$(printf '%s\n' "$BODY" | python3 -c 'import json,sys; print(json.load(sys.stdin)["sandboxID"])')"
log "sandbox $SBX_ID"

cleanup() {
  if [ "${KEEP_SANDBOX:-0}" = "1" ]; then
    log "KEEP_SANDBOX=1; leaving $SBX_ID"
    return
  fi
  curl -sS -o /dev/null -X DELETE "$API_URL/sandboxes/$SBX_ID" -H "X-API-Key: $API_KEY" || true
  log "deleted sandbox $SBX_ID"
}
trap cleanup EXIT

# Map this live sandbox → agent_1 so chain B injects ghs_mock for api.github.com.
log "PUT gateway binding for $SBX_ID"
curl -sf -X PUT "http://127.0.0.1:9002/mock/v1/bindings/$SBX_ID" \
  -H 'content-type: application/json' \
  -d '{"binding_id":"bind_e2b","actor":"user_e2b","workload":"agent_1","access_jwt":"platform.jwt"}' >/dev/null
curl -sf -X PUT "http://127.0.0.1:9002/mock/v1/connectors" \
  -H 'content-type: application/json' \
  -d '{"identity":"agent_1","host":"api.github.com","connection_id":"conn_gh","credential":"ghs_mock"}' >/dev/null

MARKER="gw-e2e-$(date +%s)"
log "guest curl $GUEST_DEST$GUEST_PATH Host=$GUEST_HOST"
GUEST_OUT="$(mktemp)"
docker run --rm --network host \
  -e E2B_API_URL="$API_URL" \
  -e E2B_API_KEY="$API_KEY" \
  -e E2B_SANDBOX_URL="$SANDBOX_URL" \
  -e SANDBOX_ID="$SBX_ID" \
  -e MARKER="$MARKER" \
  -e GUEST_PATH="$GUEST_PATH" \
  -e GUEST_HOST="$GUEST_HOST" \
  -e GUEST_DEST="$GUEST_DEST" \
  -e GUEST_METHOD=GET \
  -v "$E2E_DIR/guest-egress.mjs:/app/guest-egress.mjs:ro" \
  "$NODE_IMG" node /app/guest-egress.mjs | tee "$GUEST_OUT"
log "guest raw written to $GUEST_OUT"

WANT_AUTH="$WANT_AUTH" python3 - <<'PY' "$GUEST_OUT"
import json, sys
want = __import__("os").environ["WANT_AUTH"]
d = json.load(open(sys.argv[1]))
body = d.get("stdout") or ""
assert d.get("exitCode") == 0, d
try:
    doc = json.loads(body)
except Exception as e:
    raise SystemExit(f"guest body not JSON: {body[:300]!r}") from e

def find_auth(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() == "authorization":
                return v if isinstance(v, str) else str(v)
        req = obj.get("request")
        if isinstance(req, dict) and isinstance(req.get("headers"), dict):
            h = {str(k).lower(): v for k, v in req["headers"].items()}
            if "authorization" in h:
                return h["authorization"]
        for v in obj.values():
            found = find_auth(v)
            if found:
                return found
    elif isinstance(obj, list):
        for v in obj:
            found = find_auth(v)
            if found:
                return found
    return ""

auth = find_auth(doc)
assert auth == want, f"authorization={auth!r} want {want!r}; body={body[:800]}"
print("injected", auth)
PY
rm -f "$GUEST_OUT"

log "pass"
log "  template=$ALIAS ($TEMPLATE_ID)"
log "  sandbox=$SBX_ID"
log "  host=$GUEST_HOST injected=$WANT_AUTH"
log "  path=sandbox → E2B HBONE → hbone-ingress → Envoy/Decision → echo"
