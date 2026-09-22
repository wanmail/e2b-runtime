# Sandbox egress HBONE tunnel (design)

Status: in progress on `feat/egress-hbone-tunnel`. Node-side CONNECT + mTLS is implemented in
`packages/orchestrator/pkg/egresstunnel`. Envoy L7 remains out of scope.

## 1. Goal

Keep `tcpfirewall` as an L4 ztunnel:

1. iptables REDIRECT (already done)
2. allow/deny from sandbox network config (already done)
3. When the sandbox has workload identity, splice the admitted TCP into an
   **HTTP/2 CONNECT** stream over **mTLS** to a platform Envoy egress gateway
4. Identify the sandbox with a **SPIFFE client certificate** on that TLS session

Do **not** parse HTTP, inject headers, or mint JWT on the node.

```
guest TCP
  → REDIRECT → tcpproxy Host/SNI peek → GetByHostPort → isEgressAllowed
      ├─ no IAM  → DialProxy (today)
      └─ IAM     → HTTP/2 CONNECT + sandbox mTLS → Envoy
                      Envoy: inner MITM + JWT + origin TLS
```

Fail **closed** if the tunnel cannot be established. Never splice to the public
origin as a fallback (that would skip identity).

## 2. Non-goals

- Implementing ztunnel (inbound, DNS, eBPF, IPv6 dual-stack, in-pod redirection)
- HTTP/1.1 CONNECT, Extended CONNECT (`:protocol`), UDP/HTTP datagrams
- Istio `x-envoy-peer-metadata` / peer-metadata-exchange
- Using customer BYOP SOCKS5 as the identity tunnel
- JWT signing keys or intercept CA private key on the orchestrator
- Changing allow/deny semantics

## 3. Wire protocol (Envoy / HBONE subset)

Outer hop (node → Envoy):

| Field | Value |
|-------|--------|
| Transport | TLS 1.2+ to `EGRESS_GATEWAY_ADDR` |
| SNI | gateway hostname |
| ALPN | `h2` |
| Client cert | X.509-SVID for this sandbox execution |
| HTTP | HTTP/2 |

CONNECT stream:

```
:method     CONNECT
:authority  <original host>:<original port>
```

`:authority` is the **guest destination**, not the gateway:

- Domain allow match: peeked HTTP Host or TLS SNI + original destination port
  (same hostname already used by `proxyWithIPVerification` to defeat `/etc/hosts` spoofing)
- CIDR-only match: `dstIP:dstPort` from SO_ORIGINAL_DST
- Empty SNI (`https://1.1.1.1`): IP:port

Bidirectional byte copy until either side closes. No extra headers required for
identity. Optional later: `x-request-id` for traces (not identity).

Go `http2.Transport` must **Dial the gateway** while setting CONNECT
`:authority` to the origin. Using the request URL as the dial target would
connect to the public destination and bypass Envoy.

## 4. When to tunnel

Tunnel iff **all** of:

1. Feature flag `egress-hbone-tunnel` is on for the team (fallback off)
2. `EGRESS_GATEWAY_ADDR` is configured on the node
3. `sbx.APIStoredConfig.GetIam()` is non-empty (create-time `iam.tokens`)
4. `sbx.Runtime.TeamID`, `SandboxID`, `ExecutionID` are all non-empty
5. `sbx.Runtime.SandboxType == sandbox` (never template-build VMs)

Otherwise L4 splice as today.

Build sandboxes have `APIStoredConfig == nil` and must stay on DialProxy.
`TeamID` is documented as best-effort on `RuntimeMetadata`; the tunnel path
**fail-closes** rather than minting a cert with a blank namespace.

IAM without a reachable gateway: fail closed (drop the guest connection).

## 5. SPIFFE identity

URI SAN (and JWT `sub` later, on the gateway):

```
spiffe://<trust_domain>/ns/<team_id>/sbx/<sandbox_id>/exec/<execution_id>
```

- `trust_domain` from env `EGRESS_SPIFFE_TRUST_DOMAIN` (example: `e2b.local`)
- IDs from `sbx.Runtime` after `GetByHostPort` — host-side slot IP, not guest claims
- `LifecycleID` is **not** in the SPIFFE path (changes every Firecracker process)
- Template ID may go in a non-critical SAN DNS or cert URI query later; v1 omits it
  to keep matching simple

### 5.1 Certificate issuance (v1)

Orchestrator holds an intermediate CA (file or PKCS#11/KMS later):

- Env: `EGRESS_TUNNEL_CA_CERT`, `EGRESS_TUNNEL_CA_KEY` (PEM paths)
- Leaf: ECDSA P-256, URI SAN as above, `NotBefore`/`NotAfter` ~1h, overlap 10m
- Cache key: `execution_id` (stable across in-place checkpoint; new execution on
  resume-from-API still gets a new id from the control plane)
- Rotate in the background before expiry; new h2 connection uses the new cert
- Envoy `require_client_certificate` + matched SPIFFE trust bundle

v1 does not talk to SPIRE. The CA is platform-owned; guests never see the key.

On `OnNetworkRelease` / `OnStopping`: drop the h2 pool entry and cached leaf for
that execution (pool is keyed by execution, limiter today uses LifecycleID).

## 6. Connection pool

One HTTP/2 TLS session **per execution**, multiplex CONNECT streams.

```
pool key = execution_id
  tls.Conn + http2.ClientConn to gateway
  N concurrent CONNECT streams (cap via flag, default 64, aligned with
  TCPFirewallMaxConnectionsPerSandbox)
```

Different sandboxes **must not** share a TLS session (different client certs).

Idle timeout: close the client conn after a quiet period (flag, default 60s).
HTTP/2 PING keepalives while streams exist.

DSCP: apply existing `egressTOS.For(sandbox)` on the **outer** TCP to the
gateway (`Control` on Dial), not on an inner splice that no longer hits the
origin from this node.

## 7. Code layout

New package, linux-tagged like `tcpfirewall`:

```
packages/orchestrator/pkg/egresstunnel/
  config.go      // gateway addr, trust domain, CA paths, timeouts
  spiffe.go      // ID formatting + validation
  ca.go          // leaf sign + cache
  pool.go        // per-execution http2 client
  connect.go     // DialTLS→gateway, CONNECT, splice
  connect_test.go
  spiffe_test.go
```

`tcpfirewall` changes (small):

- `proxyDeps` grows optional `Tunnel *egresstunnel.Client` (nil = disabled)
- After `isEgressAllowed` in `domainHandler` / `cidrOnlyHandler`, if
  `tunnel.Should(sbx)` then `tunnel.Handle(ctx, c)` instead of `proxy` /
  `proxyWithIPVerification`
- Metrics: `DecisionTunneled`, errors `tunnel_dial`, `tunnel_connect`, `tunnel_cert`

`packages/orchestrator/pkg/sandbox/network/pool.go` `Config`:

```
EGRESS_GATEWAY_ADDR            host:port, empty = off
EGRESS_SPIFFE_TRUST_DOMAIN     default e2b.local
EGRESS_TUNNEL_CA_CERT          PEM path
EGRESS_TUNNEL_CA_KEY           PEM path
```

`packages/orchestrator/main.go` `defaultEgressFactory`: still `tcpfirewall.New`,
pass tunnel client constructed from `deps.Config` + `deps.FeatureFlags`.

Do **not** replace `EgressFactory` with a second proxy implementation. Tunneling
is a branch after allow, not a parallel EgressProxy. `CABundle()` stays empty
in OSS tcpfirewall; intercept CA belongs on Envoy and can be pushed via envd
from a later factory hook if the guest must trust the gateway MITM CA (that
PEM is **public** CA, not the JWT signer). Guest trust of the intercept CA is
required for L7 but is an envd `caBundle` concern, not the CONNECT client.

### 7.1 Guest intercept CA vs tunnel CA

Two different CAs:

| CA | Who holds key | Who trusts it |
|----|----------------|---------------|
| Tunnel CA | orchestrator (signs sandbox client certs) | Envoy |
| Intercept CA | Envoy (MITM toward guest) | guest via `POST /init` `caBundle` |

OSS `CABundle()` returning empty is OK until Envoy MITM is on; then the
orchestrator must ship the **intercept CA certificate only** (already plumbed).

## 8. Handler sequence

```
HandleConn
  GetByHostPort
  limiter.TryAcquire(LifecycleID)
  getOriginalDst
  domainHandler / cidrOnlyHandler
    isEgressAllowed → false: close
    ShouldTunnel(sbx):
      origAuthority = host:port or ip:port
      stream = pool.Connect(ctx, sbx, origAuthority)
      splice(guestConn, stream)   // peeked bytes already replayed by tcpproxy.Conn
    else:
      proxy / proxyWithIPVerification  // unchanged
```

`tcpproxy.Conn.Read` replays peeked Host/SNI bytes; splice must use `c.conn`
(the wrapper), not `UnderlyingConn`, so the origin Envoy inner TLS inspector
sees a complete ClientHello.

## 9. Interaction with BYOP

If `egress_proxy_address` is set, current code may loosen kernel rules and
hand TCP to a userspace SOCKS5 path (`SupportsBYOP` is false on OSS
tcpfirewall today).

v1: if BYOP is configured **and** IAM is set, **reject at API or fail closed
on the node** (ambiguous: customer proxy vs platform identity). Do not CONNECT
to Envoy and SOCKS5 the same flow. Track a follow-up: IAM ⇒ platform tunnel
wins, BYOP ignored or admission error.

## 10. Observability

NDJSON logs (orchestrator logger): `sandbox_id`, `execution_id`, `team_id`,
`tunnel_authority`, `error.type`. No cert PEM, no JWT.

Metrics (extend `tcpfirewall` meters):

- `egress.tunnel.streams` {decision=opened|failed, protocol}
- `egress.tunnel.dial` latency histogram
- `egress.tunnel.pool_conns` gauge by node

Tracing: optional span `egress.tunnel.connect` when
`egress-proxy-intercept-tracing` is on (reuse the existing flag; it already
describes TLS-intercepted egress).

## 11. Tests

Unit (no Envoy):

- SPIFFE formatting / reject empty TeamID
- Leaf cache keyed by execution_id; rotation
- `http2.Transport` fake: DialTLS records gateway addr; CONNECT `:authority`
  is origin
- splice with a `tcpproxy.Conn`-like peeked prefix
- ShouldTunnel table: nil iam, build type, empty team, flag off

Integration (httptest HTTP/2 server with `require_client_cert`):

- Guest-like TCP → handler → CONNECT bytes appear on test server
- Wrong CA: guest conn closed, no origin dial
- Gateway down: fail closed

Do not hit a real Envoy in unit CI. A later soak can point
`EGRESS_GATEWAY_ADDR` at a local Envoy with CONNECT-only.

## 12. Envoy peer contract (out of this repo)

Minimum for the tunnel to be useful:

1. Downstream TLS, ALPN `h2`, `require_client_certificate`, trust tunnel CA
2. HCM with HTTP/2, `connect_matcher`, `upgrade_type: CONNECT`
3. **Inner** filter chain after CONNECT: TLS inspector + HCM if JWT injection
   is required. Default `connect_config: {}` is L4 passthrough and will **not**
   add JWT to guest HTTPS.

JWT minting, `${iam:name}` header rewrite, and origin TLS verify live there.
Runtime only guarantees: Envoy can authenticate the sandbox and receive the
original destination in `:authority`.

## 13. Rollout

1. Flag default off; DialProxy unchanged
2. Staging: gateway CONNECT-only (no MITM) — prove identity + dest
3. Gateway inner MITM + JWT; ship intercept CA via `CABundle()`
4. Enable per team (`enable-sandbox-iam-tokens` already gates IAM admission)

## 14. Development cost (runtime)

Estimates are engineering-weeks for someone already fluent in this tree.
Envoy L7 is **not** included.

| Work | Weeks | Notes |
|------|------:|-------|
| Flag, env config, `ShouldTunnel` | 0.3 | follow `NetworkTransformRulesFlag` |
| SPIFFE leaf CA + cache + tests | 1.0 | key loading, rotation, fail-closed TeamID |
| h2 CONNECT client, pool, splice | 1.5 | DialTLS vs `:authority` is the sharp edge |
| tcpfirewall branch + DSCP + metrics | 0.7 | both domain and cidr handlers |
| Unit + fake-h2 integration tests | 1.0 | peeked `tcpproxy.Conn` |
| BYOP / IAM admission conflict | 0.3 | API 400 or node fail-closed |
| Flag rollout + runbooks | 0.5 | |
| **Runtime total** | **~5.3** | ~4–6 with review/CI |
| Envoy inner MITM + JWT (other repo) | 2–4 | not this branch |

Risks that add time:

- Go HTTP/2 CONNECT + custom Dial is under-documented; budget a spike (2–3 days)
- `tcpproxy.Conn` splice vs `UnderlyingConn` (wrong choice = broken inner TLS)
- Resume/fork: IAM is not inherited on fork (already API policy); pool must
  not leak across `ExecutionID` changes
- Connection limiter uses `LifecycleID` while tunnel pool uses `ExecutionID` —
  document and test pause/resume

## 15. Implementation order on this branch

1. `pkg/egresstunnel` SPIFFE + CA + tests (no tcpfirewall hook)
2. CONNECT client against `httptest` HTTP/2
3. Wire `ShouldTunnel` after allow; default flag off
4. Metrics / limiter / pool teardown on `OnStopping`
5. Admission: IAM + BYOP mutually exclusive
6. Envoy CONNECT-only soak (manual)

Do not land JWT or MITM in `tcpfirewall`.
