# Sandbox egress path

Guest packets leave the VM, hit the slot firewall, and only admitted **TCP** may
be tunneled. UDP and ICMP never enter the tunnel.

```
[ Firecracker VM — guest kernel ]
  eth0
        | virtio-net          the VM ends here
[ host, slot netns ns-<idx> ]
  tap0
    nftables slot-firewall    iifname tap0; not inside the VM
  vpeer
        | veth pair
[ host netns ]
  veth-<idx>
    TCP REDIRECT → tcpfirewall (orchestrator process)
       ├─ denied → close
       ├─ egressProxy set → SOCKS5
       ├─ else IAM + gateway → HBONE
       └─ else direct dial
    UDP / ICMP are not redirected
```

HBONE wire details: [egress-hbone.md](./egress-hbone.md).

## Firecracker vs E2B

Firecracker stops at the virtio device. Everything after `tap0` — namespaces,
routes, `slot-firewall`, the TCP redirect, and the tunnel — is E2B orchestrator
code on the host. Firecracker does not ship this firewall and does not see
these rules.

| | Firecracker | E2B orchestrator |
|--|-------------|------------------|
| Guest kernel and virtio-net device | yes | no |
| Which host fd backs that device | opens the `tap0` fd it is given | creates `tap0` and passes it in |
| Slot netns, `tap0`, `vpeer` / `veth-<idx>`, addresses, routes | no | yes |
| `slot-firewall` policy (`allowOut`, `denyOut`, `allowPorts`, `denyPorts`) | no | yes, installed into stock nftables |
| TCP redirect into the proxy | no | yes (iptables, or `v2-host-firewall` when `NETWORK_VERSION=2`) |
| Host/SNI check, SOCKS5, HBONE | no | yes, `tcpfirewall` in the orchestrator process |

Two different boundaries:

- **VM isolation** is Firecracker. A guest that cannot break the VMM cannot open the host netns or rewrite `slot-firewall`.
- **Egress policy** is E2B. It is the default-allow filter described below, not a second hypervisor. It does not contain a guest that has already escaped Firecracker.

## What is stock, what is ours

nftables and iptables are stock Linux netfilter. Both are open source (in-tree
kernel filter, plus the netfilter userspace tools). This repo does not fork or
patch either of them.

The orchestrator only parses sandbox network config and installs rules into
the slot's network namespace:

| Piece | Role | Code |
|-------|------|------|
| Kernel nftables | Evaluates the filter we install. UDP and ICMP allow/deny stop here. | not modified |
| `github.com/google/nftables` | Netlink client. Builds expressions and `Flush`es them into table `slot-firewall`. | library, not a fork |
| `github.com/ngrok/firewall_toolkit` | Helper for the IPv4 allow/deny sets in that table. | library, not a fork |
| Kernel iptables nat `REDIRECT` | Hijacks admitted TCP into the local proxy. | not modified; called via `github.com/coreos/go-iptables` |
| tcpfirewall | Our process. Reads Host/SNI, applies TCP allow/deny, then picks SOCKS5, HBONE, or a direct dial. | `packages/orchestrator/pkg/tcpfirewall` |

So a config change is: API JSON → orchestrator rule list → netlink `ApplyRules`.
There is no second copy of nftables to maintain. TCP policy that needs a
hostname cannot be expressed as an nftables rule, which is why that half stays
in the Go proxy.

## 1. From the VM to the host

`slot-firewall` is not inside Firecracker. The guest has its own kernel and a
virtio NIC. Nothing in that kernel is the slot table, and the guest cannot see
or change it.

The host side of the virtio NIC is `tap0`, created in the slot network
namespace `ns-<idx>`. Firecracker opens that tap. A packet leaves the guest,
crosses virtio, and appears on `tap0` already on the host.

| Interface | Where it lives | Role |
|-----------|----------------|------|
| guest `eth0` | inside the VM | guest stack; gateway is the tap address |
| `tap0` | slot netns | host end of the virtio NIC. `slot-firewall` matches `iifname tap0` |
| `vpeer` | slot netns | slot end of the veth pair. Default route in the slot netns points at the host end |
| `veth-<idx>` | host netns | host end of the same veth, moved here after it is created |

`slot-firewall` (`inet` table, chain `PREROUTE_FILTER`, priority `-150`) runs
in the slot netns on packets arriving from `tap0`, before they are routed out
`vpeer`. It decides UDP, ICMP, and the always-on private ranges. User TCP
policy is not dropped here, so TCP continues and can still be read for Host or
SNI.

Packets that pass are routed across the veth and show up on `veth-<idx>` in
the host network namespace. TCP is hijacked there, still on the host, into the
orchestrator's tcpfirewall. The listener is a host process, not a guest
process.

Which redirect is installed depends on `NETWORK_VERSION` (default `1`):

| Version | Where TCP is redirected |
|---------|-------------------------|
| 1 | iptables nat `PREROUTING`, `-i veth-<idx>` |
| 2 | nftables table `v2-host-firewall` on the host, `iifname @v2_veths` |

Both deliver the connection to the same local tcpfirewall ports:

| Original dport | Listener | What the proxy can see |
|----------------|----------|------------------------|
| 80 | HTTP | Host header |
| 443 | TLS | SNI |
| any other | other | destination IP and port only |

The original destination is recovered with `SO_ORIGINAL_DST`. Bytes peeked for
Host or SNI are replayed onto the upstream connection.

UDP and ICMP are not redirected. A domain name is invisible to them.

## 2. Firewall

Default is **allow**. `allowOut` / a matching `allowPorts` beat every deny.
Omitting `allowPorts` and `denyPorts` keeps the old IP/CIDR behavior.

| Field | Match |
|-------|--------|
| `allowOut` | peer, every protocol, every port. Domains need `denyOut: ["0.0.0.0/0"]`. |
| `denyOut` | IPv4/CIDR, every protocol, every port. No domains. |
| `allowPorts` | peer + protocol + optional inclusive port range |
| `denyPorts` | same shape, but deny |

Protocol defaults to TCP when `port` is set. ICMP takes no port. Omit both
`protocol` and `port` to match every protocol and port for that peer. UDP and
ICMP peers must be IPv4 or CIDR. Domain peers are TCP-only, and only on flows
that expose a hostname (TCP 80 and 443).

Evaluation order for one flow:

1. `allowOut` match → allow
2. `allowPorts` protocol/port match → allow
3. `denyPorts` protocol/port match → deny
4. `denyOut` match → deny
5. peer appears only in `allowPorts`, and this port/protocol did not match → deny
6. default allow

A peer listed only in `allowPorts` is limited to those slices. The same peer in
`allowOut` stays open on every port. Other peers are unchanged.

`denyPorts` is how to deny one protocol without `denyOut: ["0.0.0.0/0"]`:

```json
"denyPorts": [{ "peer": "0.0.0.0/0", "protocol": "UDP" }]
```

TCP and ICMP stay on the default policy. To punch a hole, add `allowPorts`
(it wins):

```json
"denyPorts": [{ "peer": "0.0.0.0/0", "protocol": "UDP" }],
"allowPorts": [{ "peer": "8.8.8.8", "protocol": "UDP", "port": 53 }]
```

Where it is enforced:

| Traffic | Where |
|---------|--------|
| UDP / ICMP allow and deny | nftables, before the TCP redirect |
| TCP allow and deny, including domains | tcpfirewall, after Host/SNI peek |
| Private ranges (`10/8`, `127/8`, …) | nftables predefined deny, before user rules |

When a domain is allowed, `8.8.8.8/32` is added to the allow set so the guest
can resolve it. That allow is every protocol to the nameserver, same as
`allowOut` domains. Denying UDP removes that path unless UDP/53 is allowed
again.

## 3. Tunnel

Only TCP that the firewall admitted is tunneled. Selection is per sandbox, not
per packet, and the two tunnels are not stacked:

| Config | Next hop | Identity |
|--------|----------|----------|
| `egressProxy` set | SOCKS5 to that address | username/password from the control plane |
| no proxy, `iam.tokens` set, node gateway configured | HBONE (TLS + client cert) | SPIFFE URI for this execution |
| neither | direct dial from the slot netns | none |

If both proxy and IAM are set, SOCKS5 wins.

Domain-matched TCP uses the hostname (SOCKS `ATYP=domain`, or a direct dial of
the name) so a guest `/etc/hosts` rewrite cannot retarget an allowed name.
CIDR-only TCP uses the original destination IP. Tunnel dial failure closes the
guest connection; it does not fall through to a direct public dial.

Build VMs are not tunneled.
