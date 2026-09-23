# HBONE e2e (local)

Four layers. Higher layers include everything below. The control-plane path
(API template + API sandbox with `iam.tokens`) is the full e2e.

SPIFFE identity lives in the **client certificate URI SAN**, minted by the
orchestrator tunnel CA at CONNECT time — not in the guest, not in JWT:

```
spiffe://<EGRESS_SPIFFE_TRUST_DOMAIN>/ns/<team_id>/sbx/<sandbox_id>/exec/<execution_id>
```

Envoy access log field `peer_uri_san` is that SAN (`%DOWNSTREAM_PEER_URI_SAN%`).

## 0. Prerequisites

- Embed compose stack healthy (`api` :3000, `orchestrator` :5008, `client-proxy` :3002)
- Docker, curl, python3, go (for layer 3/4 install)
- Root/passwordless sudo for installing the orchestrator binary and host certs
- `embed/compose/compose.override.yaml` with `EGRESS_*` (checked in)

The orchestrator process is `nsenter -t 1`, so it reads **host** paths. Copy
certs to `/var/lib/e2b/egress-certs`; do not rely on container volume mounts.

When `EGRESS_GATEWAY_ADDR` is set, `packages/orchestrator/main.go` forces
`egress-hbone-tunnel` on (no LaunchDarkly). API still needs
`enable-sandbox-iam-tokens` (true in `ENVIRONMENT=local` / development).

## 1. Mock Envoy only

```bash
cd packages/orchestrator/dev/egresstunnel
./certs/gen.sh
docker compose up --build -d
```

| Port  | Service |
|-------|---------|
| 15008 | Envoy HBONE (mTLS, ALPN=h2, CONNECT → capture) |
| 9901  | Envoy admin |
| 18080 | Capture HTTP (direct; inner plaintext dump) |

## 2. Client smoke (no Firecracker)

From `packages/orchestrator`:

```bash
go run ./cmd/hbone-smoke
```

Expects Envoy `CONNECT` + `spiffe://e2b.local/ns/team-smoke/sbx/sbx-smoke/exec/exec-smoke`
and capture `POST /hbone-smoke`.

## 3. Go tests (no API)

```bash
# Alpine “guest” container → egresstunnel.Handle → Envoy
go test ./pkg/egresstunnel/ -count=1 -timeout 2m -run TestE2E_SandboxRequestToMockEnvoy

# root + CGO: real netns + tcpfirewall REDIRECT
sudo go test ./pkg/tcpfirewall/ -count=1 -timeout 2m -run TestE2E_SandboxHTTPToMockEnvoy
```

## 4. API e2e (Firecracker + control plane)

Guest TCP → slot nftables REDIRECT → tcpfirewall → HBONE CONNECT+mTLS → mock
Envoy → capture. Template and sandbox are created through the public API.

```bash
cd packages/orchestrator/dev/egresstunnel/e2e
chmod +x *.sh

# first time on a machine: mock + HBONE binary + recreate orchestrator + API path
./run.sh

# orchestrator already running with EGRESS_* and the HBONE binary
SKIP_INSTALL=1 ./run.sh

# pieces
./mock-up.sh
./install-hbone-orchestrator.sh   # stop orch, swap binary, recreate
./api-e2e.sh                      # template + sandbox + guest curl + log asserts
```

`api-e2e.sh` does:

1. `Template.build` → `POST /v3/templates` + start build (alias `hbone-e2e`, reused if ready)
2. `POST /sandboxes` with

   ```json
   {
     "templateID": "hbone-e2e",
     "iam": {
       "tokens": {
         "default": { "audience": "egress-e2e", "tokenType": "JWT-SVID" }
       }
     }
   }
   ```

3. Connect envd via `E2B_SANDBOX_URL` (client-proxy `:3002`, not `*.e2b.app`)
4. Guest: `curl POST http://203.0.113.80/hbone-api-e2e` with `Host: api.example.com`
   (documentation IP; mock Envoy never dials `:authority`)
5. Assert guest body `ok: request captured`, capture dump, Envoy CONNECT + SPIFFE

`BUILD_MOCK=1 ./mock-up.sh` rebuilds the capture image.

Useful env:

| Var | Meaning |
|-----|---------|
| `TEMPLATE_ALIAS` | default `hbone-e2e` |
| `FORCE_REBUILD=1` | rebuild the alias |
| `KEEP_SANDBOX=1` | skip DELETE |
| `SKIP_BUILD=1` | install uses `/tmp/orchestrator-hbone` as-is |
| `E2B_API_KEY` | else `e2b_seed-state` `/run/e2b/team-api-key` |

Inspect:

```bash
docker compose -f ../docker-compose.yml logs envoy capture
```

Pass looks like:

```
hbone-e2e: pass
  template=hbone-e2e (<templateID>)
  sandbox=<sandboxID>
  spiffe=spiffe://e2b.local/ns/<teamUUID>/sbx/<sandboxID>/exec/<executionID>
  capture POST /hbone-api-e2e marker=hbone-api-e2e-<unix>
```

### Fail-closed

If IAM is set but the tunnel cannot be established, guest curl fails
(timeout / connection reset). It must not reach the public origin.

Build VMs (`SandboxType != sandbox`, no `iam`) stay on DialProxy and must not
appear in Envoy `peer_uri_san`.
