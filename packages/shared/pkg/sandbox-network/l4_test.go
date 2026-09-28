package sandbox_network

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func uint32p(v uint32) *uint32 { return &v }

func TestNormalizeEgressPortRules(t *testing.T) {
	t.Parallel()

	rules, err := NormalizeEgressPortRules([]EgressPortRule{
		{Peer: "8.8.8.8", Protocol: "udp", Port: uint32p(53)},
		{Peer: "example.com", Port: uint32p(443)},
		{Peer: "10.0.0.0/8", Protocol: "ICMP"},
		{Peer: "1.2.3.4"},
	})
	require.NoError(t, err)
	assert.Equal(t, []EgressPortRule{
		{Peer: "8.8.8.8/32", Protocol: EgressProtoUDP, Port: uint32p(53)},
		{Peer: "example.com", Protocol: EgressProtoTCP, Port: uint32p(443)},
		{Peer: "10.0.0.0/8", Protocol: EgressProtoICMP},
		{Peer: "1.2.3.4/32"},
	}, rules)

	_, err = NormalizeEgressPortRules([]EgressPortRule{{Peer: "example.com", Protocol: "UDP", Port: uint32p(53)}})
	require.Error(t, err)
	_, err = NormalizeEgressPortRules([]EgressPortRule{{Peer: "10.0.0.0/8", Protocol: "ICMP", Port: uint32p(1)}})
	require.Error(t, err)
	_, err = NormalizeEgressPortRules([]EgressPortRule{{Peer: "10.0.0.0/8", Protocol: "SCTP", Port: uint32p(1)}})
	require.Error(t, err)
	_, err = NormalizeEgressPortRules(nil)
	require.NoError(t, err)
}

func TestEvalTCPPortRules(t *testing.T) {
	t.Parallel()

	rules := []EgressPortRule{
		{Peer: "1.2.3.4/32", Protocol: EgressProtoTCP, Port: uint32p(443)},
		{Peer: "example.com", Protocol: EgressProtoTCP, Port: uint32p(443)},
		{Peer: "9.9.9.9/32", Protocol: EgressProtoUDP, Port: uint32p(53)},
	}
	ip := net.ParseIP("1.2.3.4")

	allowed, err := EvalTCPPortRules(rules, "", ip, 443)
	require.NoError(t, err)
	assert.True(t, allowed.Allowed)
	assert.False(t, allowed.Restricted)
	assert.False(t, allowed.Domain)

	blocked, err := EvalTCPPortRules(rules, "", ip, 80)
	require.NoError(t, err)
	assert.False(t, blocked.Allowed)
	assert.True(t, blocked.Restricted)

	other, err := EvalTCPPortRules(rules, "", net.ParseIP("8.8.8.8"), 80)
	require.NoError(t, err)
	assert.False(t, other.Allowed)
	assert.False(t, other.Restricted)

	domain, err := EvalTCPPortRules(rules, "example.com", net.ParseIP("9.9.9.9"), 443)
	require.NoError(t, err)
	assert.True(t, domain.Allowed)
	assert.True(t, domain.Domain)

	udpOnly, err := EvalTCPPortRules(rules, "", net.ParseIP("9.9.9.9"), 443)
	require.NoError(t, err)
	assert.False(t, udpOnly.Allowed)
	assert.True(t, udpOnly.Restricted)

	absent, err := EvalTCPPortRules(nil, "example.com", ip, 80)
	require.NoError(t, err)
	assert.False(t, absent.Allowed)
	assert.False(t, absent.Restricted)
}

func TestEvalTCPDenyRules(t *testing.T) {
	t.Parallel()

	rules := []EgressPortRule{
		{Peer: "0.0.0.0/0", Protocol: EgressProtoUDP},
		{Peer: "1.2.3.4/32", Protocol: EgressProtoTCP, Port: uint32p(22)},
	}

	udpDoesNotDenyTCP, err := EvalTCPDenyRules(rules, "", net.ParseIP("8.8.8.8"), 53)
	require.NoError(t, err)
	assert.False(t, udpDoesNotDenyTCP.Denied)

	ssh, err := EvalTCPDenyRules(rules, "", net.ParseIP("1.2.3.4"), 22)
	require.NoError(t, err)
	assert.True(t, ssh.Denied)
	assert.False(t, ssh.Domain)

	https, err := EvalTCPDenyRules(rules, "", net.ParseIP("1.2.3.4"), 443)
	require.NoError(t, err)
	assert.False(t, https.Denied)
}

func TestPlanNonTCPDeny(t *testing.T) {
	t.Parallel()

	plan := PlanNonTCPDeny([]EgressPortRule{
		{Peer: "0.0.0.0/0", Protocol: EgressProtoUDP},
		{Peer: "10.0.0.0/8", Protocol: EgressProtoICMP},
		{Peer: "1.1.1.1/32"},
		{Peer: "example.com", Protocol: EgressProtoTCP, Port: uint32p(443)},
	})

	assert.Equal(t, []string{"1.1.1.1/32"}, plan.DenyCIDRs)
	assert.Equal(t, []EgressPortRule{
		{Peer: "0.0.0.0/0", Protocol: EgressProtoUDP},
		{Peer: "10.0.0.0/8", Protocol: EgressProtoICMP},
	}, plan.Drops)
}

func TestPlanNonTCP(t *testing.T) {
	t.Parallel()

	plan := PlanNonTCP([]EgressPortRule{
		{Peer: "8.8.8.8/32", Protocol: EgressProtoUDP, Port: uint32p(53)},
		{Peer: "1.1.1.1/32", Protocol: EgressProtoTCP, Port: uint32p(443)},
		{Peer: "10.0.0.0/8", Protocol: EgressProtoICMP},
		{Peer: "192.168.0.0/16"},
		{Peer: "example.com", Protocol: EgressProtoTCP, Port: uint32p(443)},
	})

	assert.Equal(t, []string{"192.168.0.0/16"}, plan.AllowCIDRs)
	assert.Equal(t, []EgressPortRule{
		{Peer: "8.8.8.8/32", Protocol: EgressProtoUDP, Port: uint32p(53)},
		{Peer: "10.0.0.0/8", Protocol: EgressProtoICMP},
	}, plan.Accepts)
	assert.Equal(t, []string{"8.8.8.8/32", "1.1.1.1/32", "10.0.0.0/8"}, plan.DropCIDRs)
}
