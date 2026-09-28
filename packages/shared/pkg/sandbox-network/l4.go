package sandbox_network

import (
	"fmt"
	"net"
	"strings"
)

const (
	// MaxEgressPortRules caps allowPorts so nftables stays a small chain.
	MaxEgressPortRules = 128

	EgressProtoTCP  = "TCP"
	EgressProtoUDP  = "UDP"
	EgressProtoICMP = "ICMP"
)

// EgressPortRule is one L4 allow. Empty Protocol and a nil Port allow every
// protocol and port for Peer (the same shape as an allowOut string). An empty
// Protocol with Port set defaults to TCP, matching Kubernetes NetworkPolicy.
// ICMP never carries a port.
//
// A peer that appears only here is limited to the listed slices. The same peer
// in the legacy allow list stays open on every port. Peers that appear in
// neither list keep the existing allow/deny/default-allow behavior.
type EgressPortRule struct {
	Peer     string  `json:"peer"`
	Protocol string  `json:"protocol,omitempty"`
	Port     *uint32 `json:"port,omitempty"`
	EndPort  *uint32 `json:"endPort,omitempty"`
}

// L4Query is one flow to match against EgressPortRule values.
type L4Query struct {
	Protocol string
	Port     uint16
	Hostname string
	IP       net.IP
}

// TCPPortDecision is the TCP-only view of allowPorts. Allowed means some rule
// permits this flow. Restricted means a rule selected the peer but none permit
// this TCP port, so the peer is closed for this port even when the global
// default is allow. Domain is set when the deciding peer is a hostname so the
// TCP proxy can keep remote-DNS behavior.
type TCPPortDecision struct {
	Allowed    bool
	Restricted bool
	Domain     bool
}

// NonTCPPlan is the kernel half of allowPorts. TCP is redirected to the
// userspace proxy and is not part of this plan. AllowCIDRs are all-protocol
// peers and belong in the existing non-TCP allow set. Accepts are UDP/ICMP
// holes. DropCIDRs are port-scoped IPv4 peers whose other non-TCP traffic
// must be dropped so a UDP/53 rule does not leave every other datagram open.
type NonTCPPlan struct {
	AllowCIDRs []string
	Accepts    []EgressPortRule
	DropCIDRs  []string
}

// HasDomainPeer reports whether any rule names a domain. Those flows need the
// default nameserver when a deny-all rule would otherwise block DNS.
func HasDomainPeer(rules []EgressPortRule) bool {
	for _, rule := range rules {
		if !IsIPOrCIDR(rule.Peer) && rule.Peer != "" {
			return true
		}
	}

	return false
}

// NormalizeEgressPortRules validates and canonicalizes allowPorts.
// An empty list returns nil. IPv4 peers are stored as CIDRs. Protocol is
// stored in uppercase; a port with no protocol becomes TCP.
func NormalizeEgressPortRules(rules []EgressPortRule) ([]EgressPortRule, error) {
	return NormalizeEgressPortList("allowPorts", rules)
}

// NormalizeEgressPortList is NormalizeEgressPortRules with the API field name
// used in errors. field is allowPorts or denyPorts.
func NormalizeEgressPortList(field string, rules []EgressPortRule) ([]EgressPortRule, error) {
	if len(rules) == 0 {
		return nil, nil
	}
	if len(rules) > MaxEgressPortRules {
		return nil, fmt.Errorf("at most %d %s rules are supported", MaxEgressPortRules, field)
	}

	out := make([]EgressPortRule, len(rules))
	for i, rule := range rules {
		normalized, err := normalizeEgressPortRule(rule)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: %w", field, i, err)
		}
		out[i] = normalized
	}

	return out, nil
}

func normalizeEgressPortRule(rule EgressPortRule) (EgressPortRule, error) {
	peer := strings.TrimSpace(rule.Peer)
	if peer == "" {
		return EgressPortRule{}, fmt.Errorf("peer is required")
	}

	protocol, err := normalizeProtocol(rule.Protocol)
	if err != nil {
		return EgressPortRule{}, err
	}
	if rule.EndPort != nil && rule.Port == nil {
		return EgressPortRule{}, fmt.Errorf("endPort requires port")
	}
	if rule.Port != nil {
		if err := validatePort(*rule.Port); err != nil {
			return EgressPortRule{}, fmt.Errorf("port: %w", err)
		}
	}
	if rule.EndPort != nil {
		if err := validatePort(*rule.EndPort); err != nil {
			return EgressPortRule{}, fmt.Errorf("endPort: %w", err)
		}
		if *rule.EndPort < *rule.Port {
			return EgressPortRule{}, fmt.Errorf("endPort %d is before port %d", *rule.EndPort, *rule.Port)
		}
	}
	if protocol == EgressProtoICMP && (rule.Port != nil || rule.EndPort != nil) {
		return EgressPortRule{}, fmt.Errorf("ICMP does not take a port")
	}
	if protocol == "" && rule.Port != nil {
		protocol = EgressProtoTCP
	}

	if IsIPOrCIDR(peer) {
		if !isIPv4Peer(peer) {
			return EgressPortRule{}, fmt.Errorf("peer %q must be an IPv4 address or CIDR", peer)
		}
		peer = AddressStringToCIDR(peer)
	} else if protocol == EgressProtoUDP || protocol == EgressProtoICMP || protocol == "" {
		return EgressPortRule{}, fmt.Errorf("peer %q is a domain, which only supports TCP", peer)
	}

	return EgressPortRule{
		Peer:     peer,
		Protocol: protocol,
		Port:     rule.Port,
		EndPort:  rule.EndPort,
	}, nil
}

func normalizeProtocol(protocol string) (string, error) {
	switch strings.ToUpper(strings.TrimSpace(protocol)) {
	case "":
		return "", nil
	case EgressProtoTCP, EgressProtoUDP, EgressProtoICMP:
		return strings.ToUpper(strings.TrimSpace(protocol)), nil
	default:
		return "", fmt.Errorf("protocol %q must be TCP, UDP, or ICMP", protocol)
	}
}

func validatePort(port uint32) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("%d is outside 1-65535", port)
	}

	return nil
}

func isIPv4Peer(peer string) bool {
	if peer == AllInternetTrafficCIDR {
		return true
	}
	if ip := net.ParseIP(peer); ip != nil {
		return ip.To4() != nil && !ip.IsUnspecified()
	}
	ip, network, err := net.ParseCIDR(peer)
	if err != nil || ip.To4() == nil || network.IP.To4() == nil {
		return false
	}
	if ip.IsUnspecified() {
		return false
	}

	return true
}

// EvalTCPPortRules matches allowPorts for a TCP flow that already survived the
// legacy allow list. Callers must apply legacy allowOut first so an all-port
// allow keeps winning.
func EvalTCPPortRules(rules []EgressPortRule, hostname string, ip net.IP, port uint16) (TCPPortDecision, error) {
	decision := TCPPortDecision{}
	for _, rule := range rules {
		domain, selected, err := peerSelected(rule.Peer, hostname, ip)
		if err != nil {
			return TCPPortDecision{}, err
		}
		if !selected {
			continue
		}
		if domain {
			decision.Domain = true
		}
		decision.Restricted = true
		if rule.matchesL4(EgressProtoTCP, port) {
			decision.Allowed = true
		}
	}
	if decision.Allowed {
		decision.Restricted = false
	}

	return decision, nil
}

// TCPDenyDecision is the TCP view of denyPorts. Denied means some rule selects
// the peer and the protocol/port. Domain is set when that peer is a hostname.
// Callers apply allows first, so a matching allow still wins.
type TCPDenyDecision struct {
	Denied bool
	Domain bool
}

// EvalTCPDenyRules matches denyPorts for a TCP flow. A UDP-only or ICMP-only
// rule does not deny TCP.
func EvalTCPDenyRules(rules []EgressPortRule, hostname string, ip net.IP, port uint16) (TCPDenyDecision, error) {
	decision := TCPDenyDecision{}
	for _, rule := range rules {
		domain, selected, err := peerSelected(rule.Peer, hostname, ip)
		if err != nil {
			return TCPDenyDecision{}, err
		}
		if !selected || !rule.matchesL4(EgressProtoTCP, port) {
			continue
		}
		decision.Denied = true
		if domain {
			decision.Domain = true
		}
	}

	return decision, nil
}

// NonTCPDenyPlan is the kernel half of denyPorts. DenyCIDRs are all-protocol
// peers and join the existing non-TCP deny set. Drops are UDP/ICMP-only.
// TCP denies stay in the userspace proxy.
type NonTCPDenyPlan struct {
	DenyCIDRs []string
	Drops     []EgressPortRule
}

// PlanNonTCPDeny classifies denyPorts for nftables. Domain peers are omitted.
func PlanNonTCPDeny(rules []EgressPortRule) NonTCPDenyPlan {
	var plan NonTCPDenyPlan
	for _, rule := range rules {
		if !IsIPOrCIDR(rule.Peer) {
			continue
		}
		if rule.Protocol == "" && rule.Port == nil {
			plan.DenyCIDRs = append(plan.DenyCIDRs, rule.Peer)
			continue
		}
		if rule.Protocol == EgressProtoUDP || rule.Protocol == EgressProtoICMP {
			plan.Drops = append(plan.Drops, rule)
		}
	}

	return plan
}

// PlanNonTCP classifies allowPorts for the nftables filter. Domain peers are
// omitted; only TCP can see a hostname.
func PlanNonTCP(rules []EgressPortRule) NonTCPPlan {
	type peerPlan struct {
		allProtocol bool
		accepts     []EgressPortRule
	}
	order := make([]string, 0)
	byPeer := make(map[string]*peerPlan)
	for _, rule := range rules {
		if !IsIPOrCIDR(rule.Peer) {
			continue
		}
		plan, ok := byPeer[rule.Peer]
		if !ok {
			plan = &peerPlan{}
			byPeer[rule.Peer] = plan
			order = append(order, rule.Peer)
		}
		if rule.Protocol == "" && rule.Port == nil {
			plan.allProtocol = true
			continue
		}
		if rule.Protocol == EgressProtoUDP || rule.Protocol == EgressProtoICMP {
			plan.accepts = append(plan.accepts, rule)
		}
	}

	var plan NonTCPPlan
	for _, peer := range order {
		item := byPeer[peer]
		if item.allProtocol {
			plan.AllowCIDRs = append(plan.AllowCIDRs, peer)
			continue
		}
		plan.DropCIDRs = append(plan.DropCIDRs, peer)
		plan.Accepts = append(plan.Accepts, item.accepts...)
	}

	return plan
}

func (r EgressPortRule) matchesL4(protocol string, port uint16) bool {
	want := strings.ToUpper(strings.TrimSpace(r.Protocol))
	if want == "" && r.Port == nil {
		return true
	}
	if want == "" {
		want = EgressProtoTCP
	}
	if !strings.EqualFold(protocol, want) {
		return false
	}
	if want == EgressProtoICMP || r.Port == nil {
		return true
	}
	end := *r.Port
	if r.EndPort != nil {
		end = *r.EndPort
	}
	got := uint32(port)

	return got >= *r.Port && got <= end
}

func peerSelected(peer, hostname string, ip net.IP) (domain bool, selected bool, err error) {
	if IsIPOrCIDR(peer) {
		cidr := AddressStringToCIDR(peer)
		_, network, parseErr := net.ParseCIDR(cidr)
		if parseErr != nil {
			return false, false, fmt.Errorf("invalid allowPorts CIDR %q: %w", peer, parseErr)
		}

		return false, network.Contains(ip), nil
	}
	if hostname == "" {
		return true, false, nil
	}

	return true, MatchDomainPattern(hostname, peer), nil
}
