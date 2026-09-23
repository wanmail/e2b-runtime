# Local HBONE mock (Envoy + capture)

Verify the orchestrator `egresstunnel` client against a Docker Envoy that
terminates HTTP/2 CONNECT over mTLS and forwards the stream to a capture
service that prints the **full guest HTTP request**.

Full ladder (smoke → go tests → **API template + IAM sandbox**) is in
[e2e/README.md](./e2e/README.md). `e2e/run.sh` is the control-plane e2e.

## Quick start

```bash
cd packages/orchestrator/dev/egresstunnel
./certs/gen.sh
docker compose up --build -d

# from packages/orchestrator
cd ../..
go run ./cmd/hbone-smoke

# sandbox e2e: Docker alpine as the guest → HBONE client → Envoy → capture
go test ./pkg/egresstunnel/ -count=1 -timeout 2m -run TestE2E_SandboxRequestToMockEnvoy

# optional (root + CGO): real netns slot + tcpfirewall REDIRECT
# sudo go test ./pkg/tcpfirewall/ -count=1 -timeout 2m -run TestE2E_SandboxHTTPToMockEnvoy

# API e2e (embed compose + Firecracker + POST /sandboxes iam.tokens)
# ./e2e/run.sh

# inspect
docker compose -f dev/egresstunnel/docker-compose.yml logs envoy capture
docker compose -f dev/egresstunnel/docker-compose.yml down
```

## What you should see

**Envoy** access log (CONNECT + SPIFFE):

```
[envoy] ... CONNECT authority=api.example.com:443
peer_uri_san=spiffe://e2b.local/ns/team-smoke/sbx/sbx-smoke/exec/exec-smoke
response=200 ...
```

**Capture** (full HTTP):

```
========== CAPTURED REQUEST ==========
POST /hbone-smoke HTTP/1.1
Host: api.example.com
X-Smoke: egresstunnel
...
hello from sandbox
======================================
```

## Ports

| Port  | Service                          |
|-------|----------------------------------|
| 15008 | Envoy HBONE (mTLS, ALPN=h2)      |
| 9901  | Envoy admin                      |
| 18080 | Capture HTTP (direct, for debug) |

## Certs

`certs/gen.sh` creates:

- `tunnel-ca.{crt,key}` — signs sandbox client leafs (smoke uses this via `LoadSigner`)
- `gateway.{crt,key}` — Envoy server cert (SAN: localhost, 127.0.0.1, gateway.local)
- `gateway-ca.crt` — trust store for the client (same as tunnel CA in this mock)

## Notes

- Key PEMs must be world-readable when bind-mounted (`gen.sh` sets `chmod 644`); Envoy runs as non-root.
- Envoy routes every CONNECT to the capture cluster (mock does not dial the real `:authority`).
- Inner traffic here is **plaintext HTTP** so capture can dump headers/body. Production guest HTTPS would need gateway MITM (out of scope for this mock).
- Envoy JSON access log (`msg=hbone_connect`) shows `authority` and `peer_uri_san` (SPIFFE). Capture logs show the full guest HTTP request.
