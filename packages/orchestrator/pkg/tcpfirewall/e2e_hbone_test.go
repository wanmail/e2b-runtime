//go:build linux

package tcpfirewall

import (
	"bufio"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/uuid"
	"github.com/launchdarkly/go-server-sdk/v7/testhelpers/ldtestdata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netns"
	"go.opentelemetry.io/otel/metric/noop"

	"github.com/e2b-dev/infra/packages/orchestrator/pkg/egresstunnel"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox"
	"github.com/e2b-dev/infra/packages/orchestrator/pkg/sandbox/network"
	"github.com/e2b-dev/infra/packages/shared/pkg/featureflags"
	"github.com/e2b-dev/infra/packages/shared/pkg/grpc/orchestrator"
	"github.com/e2b-dev/infra/packages/shared/pkg/logger"
	"github.com/e2b-dev/infra/packages/shared/pkg/sandboxtypes"
)

// High slot indexes so this e2e never collides with the network package's
// privileged tests (those start at 30000).
var e2eSlotIdx atomic.Int32

const (
	e2eGuestHost = "api.example.com"
	e2eGuestPath = "/sandbox-e2e"
	e2eMarker    = "hello from sandbox e2e"
	// TEST-NET-3: peeked HTTP Host is the allow/CONNECT authority; this IP is only SO_ORIGINAL_DST.
	e2eOrigDst = "203.0.113.80"
)

// TestE2E_SandboxHTTPToMockEnvoy creates a sandbox (IAM + network slot),
// sends plaintext HTTP from inside the slot netns, and checks that tcpfirewall
// tunnels it over CONNECT+mTLS to the local Docker Envoy mock, which dumps the
// full request on the capture backend.
func TestE2E_SandboxHTTPToMockEnvoy(t *testing.T) { //nolint:paralleltest // host netns, iptables, docker compose
	if os.Geteuid() != 0 {
		t.Skip("requires root for sandbox netns + iptables REDIRECT")
	}
	if os.Getenv("CGO_ENABLED") == "0" {
		t.Skip("requires CGO (sandbox netns stack)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not on PATH")
	}

	mockRoot := findMockRoot(t)
	ensureMockCerts(t, mockRoot)
	startMockEnvoy(t, mockRoot)

	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	t.Cleanup(cancel)

	td := ldtestdata.DataSource()
	td.Update(td.Flag(featureflags.EgressHBONETunnelFlag.Key()).BooleanFlag().VariationForAll(true))
	ff, err := featureflags.NewClientWithDatasource(td)
	require.NoError(t, err)

	signer, err := egresstunnel.LoadSigner(
		filepath.Join(mockRoot, "certs", "tunnel-ca.crt"),
		filepath.Join(mockRoot, "certs", "tunnel-ca.key"),
	)
	require.NoError(t, err)
	gwPEM, err := os.ReadFile(filepath.Join(mockRoot, "certs", "gateway-ca.crt"))
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(gwPEM))

	tunnel, err := egresstunnel.New(egresstunnel.Config{
		GatewayAddr: "127.0.0.1:15008",
		TrustDomain: "e2b.local",
		ServerName:  "localhost",
		RootCAs:     roots,
		Signer:      signer,
		DialTimeout: 5 * time.Second,
	}, ff, logger.L())
	require.NoError(t, err)
	t.Cleanup(func() { _ = tunnel.Close() })

	netCfg, err := network.ParseConfig()
	require.NoError(t, err)
	netCfg.SandboxTCPFirewallHTTPPort = mustFreePort(t)
	netCfg.SandboxTCPFirewallTLSPort = mustFreePort(t)
	netCfg.SandboxTCPFirewallOtherPort = mustFreePort(t)

	sandboxes := sandbox.NewSandboxesMap()
	fw := New(logger.L(), netCfg, sandboxes, noop.NewMeterProvider(), ff)
	fw.SetTunnel(tunnel) // must be before Start: Start copies tunnel into route deps

	go func() {
		_ = fw.Start(ctx)
	}()
	t.Cleanup(func() { _ = fw.Close(context.WithoutCancel(ctx)) })
	waitTCP(t, fmt.Sprintf("127.0.0.1:%d", netCfg.SandboxTCPFirewallHTTPPort), 5*time.Second)

	idx := 32100 + int(e2eSlotIdx.Add(1))
	slot, err := network.NewSlot("hbone-e2e", idx, netCfg, fw)
	require.NoError(t, err)
	require.NoError(t, slot.CreateNetwork(ctx))
	t.Cleanup(func() { _ = slot.RemoveNetwork() })
	snatAllEth0(t, slot)

	teamID := "team-e2e"
	sandboxID := "sbx-e2e-" + uuid.NewString()[:8]
	executionID := "exec-e2e-" + uuid.NewString()[:8]
	sbx := &sandbox.Sandbox{
		LifecycleID: uuid.NewString(),
		Metadata: &sandbox.Metadata{
			Config: sandbox.NewConfig(sandbox.Config{}),
			Runtime: sandboxtypes.RuntimeMetadata{
				SandboxID:   sandboxID,
				ExecutionID: executionID,
				TeamID:      teamID,
				SandboxType: sandboxtypes.SandboxTypeSandbox,
			},
		},
		Resources: &sandbox.Resources{Slot: slot},
		APIStoredConfig: &orchestrator.SandboxConfig{
			Iam: &orchestrator.SandboxIam{
				Tokens: map[string]*orchestrator.SandboxIamToken{
					"default": {Audience: "e2e", TokenType: "urn:ietf:params:oauth:token-type:jwt"},
				},
			},
		},
	}
	sandboxes.AssignNetwork(ctx, sbx)

	wantSPIFFE := fmt.Sprintf("spiffe://e2b.local/ns/%s/sbx/%s/exec/%s", teamID, sandboxID, executionID)

	status, body := postHTTPFromNamespace(t, ctx, slot, e2eOrigDst+":80", e2eGuestHost, e2eGuestPath, e2eMarker)
	require.Equal(t, "200", status, "guest HTTP through the tunnel: body=%q", body)
	require.Contains(t, body, "ok: request captured")

	captureLogs := composeLogs(t, mockRoot, "capture")
	require.Contains(t, captureLogs, "POST "+e2eGuestPath)
	require.Contains(t, captureLogs, e2eMarker)
	require.Contains(t, captureLogs, "Host: "+e2eGuestHost)

	envoyLogs := composeLogs(t, mockRoot, "envoy")
	require.Contains(t, envoyLogs, wantSPIFFE)
	require.Contains(t, envoyLogs, `"authority":"`+e2eGuestHost+`:80"`)
	assert.Contains(t, envoyLogs, `"method":"CONNECT"`)
}

func snatAllEth0(t *testing.T, slot *network.Slot) {
	t.Helper()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	host, err := netns.Get()
	require.NoError(t, err)
	defer func() {
		require.NoError(t, netns.Set(host))
		_ = host.Close()
	}()

	target, err := netns.GetFromName(slot.NamespaceID())
	require.NoError(t, err)
	defer func() { _ = target.Close() }()
	require.NoError(t, netns.Set(target))

	tables, err := iptables.New()
	require.NoError(t, err)
	// Production SNAT only rewrites the Firecracker tap address. This e2e
	// originates from the netns local stack (eth0), so stamp HostIP the same way.
	err = tables.Append("nat", "POSTROUTING", "-o", slot.VpeerName(), "-j", "SNAT", "--to", slot.HostIPString())
	require.NoError(t, err)
}

func postHTTPFromNamespace(t *testing.T, ctx context.Context, slot *network.Slot, dialAddr, host, path, body string) (status, respBody string) {
	t.Helper()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hostNS, err := netns.Get()
	require.NoError(t, err)
	defer func() {
		require.NoError(t, netns.Set(hostNS))
		_ = hostNS.Close()
	}()

	target, err := netns.GetFromName(slot.NamespaceID())
	require.NoError(t, err)
	defer func() { _ = target.Close() }()
	require.NoError(t, netns.Set(target))

	d := net.Dialer{Timeout: 8 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", dialAddr)
	require.NoError(t, err, "dial from sandbox netns")
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))

	req := fmt.Sprintf(
		"POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nX-E2E: sandbox-hbone\r\nConnection: close\r\n\r\n%s",
		path, host, len(body), body,
	)
	_, err = io.WriteString(conn, req)
	require.NoError(t, err)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return fmt.Sprintf("%d", resp.StatusCode), string(b)
}

func mustFreePort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	var p int
	_, err = fmt.Sscanf(portStr, "%d", &p)
	require.NoError(t, err)

	return uint16(p)
}

func waitTCP(t *testing.T, addr string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	var last error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()

			return
		}
		last = err
		time.Sleep(50 * time.Millisecond)
	}
	require.NoError(t, last, "timeout waiting for %s", addr)
}

func findMockRoot(t *testing.T) string {
	t.Helper()
	if v := os.Getenv("HBONE_MOCK_ROOT"); v != "" {
		return v
	}
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	root := filepath.Join(filepath.Dir(file), "..", "..", "dev", "egresstunnel")
	_, err := os.Stat(filepath.Join(root, "docker-compose.yml"))
	require.NoError(t, err, "dev/egresstunnel mock stack")

	return root
}

func ensureMockCerts(t *testing.T, root string) {
	t.Helper()
	need := []string{"tunnel-ca.crt", "tunnel-ca.key", "gateway.crt", "gateway.key", "gateway-ca.crt"}
	for _, n := range need {
		if _, err := os.Stat(filepath.Join(root, "certs", n)); err != nil {
			cmd := exec.Command(filepath.Join(root, "certs", "gen.sh"))
			cmd.Dir = root
			out, err := cmd.CombinedOutput()
			require.NoError(t, err, "gen.sh: %s", out)

			return
		}
	}
}

func startMockEnvoy(t *testing.T, root string) {
	t.Helper()
	cmd := exec.Command("docker", "compose", "-f", filepath.Join(root, "docker-compose.yml"), "up", "-d")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "docker compose up: %s", out)
	waitTCP(t, "127.0.0.1:15008", 20*time.Second)
}

func composeLogs(t *testing.T, root, service string) string {
	t.Helper()
	cmd := exec.Command("docker", "compose", "-f", filepath.Join(root, "docker-compose.yml"), "logs", "--no-color", "--tail=80", service)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "compose logs %s: %s", service, out)

	return strings.TrimSpace(string(out))
}
