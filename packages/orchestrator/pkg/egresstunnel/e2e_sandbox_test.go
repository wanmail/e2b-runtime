package egresstunnel

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/e2b-dev/infra/packages/shared/pkg/logger"
)

const (
	e2eGuestHost = "api.example.com"
	e2eGuestPath = "/sandbox-e2e"
	e2eMarker    = "hello from sandbox e2e"
)

// TestE2E_SandboxRequestToMockEnvoy creates a sandbox identity, starts a Docker
// sandbox (alpine+wget, host net), and has it send HTTP into the node HBONE
// client. Envoy must see CONNECT + SPIFFE and capture must dump the full request.
func TestE2E_SandboxRequestToMockEnvoy(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not on PATH")
	}

	mockRoot := findMockRoot(t)
	ensureMockCerts(t, mockRoot)
	startMockEnvoy(t, mockRoot)

	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	t.Cleanup(cancel)

	signer, err := LoadSigner(
		filepath.Join(mockRoot, "certs", "tunnel-ca.crt"),
		filepath.Join(mockRoot, "certs", "tunnel-ca.key"),
	)
	require.NoError(t, err)
	gwPEM, err := os.ReadFile(filepath.Join(mockRoot, "certs", "gateway-ca.crt"))
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(gwPEM))

	client, err := New(Config{
		GatewayAddr: "127.0.0.1:15008",
		TrustDomain: "e2b.local",
		ServerName:  "localhost",
		RootCAs:     roots,
		Signer:      signer,
		DialTimeout: 5 * time.Second,
	}, nil, logger.L())
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	teamID := "team-e2e"
	sandboxID := "sbx-e2e-" + uuid.NewString()[:8]
	executionID := "exec-e2e-" + uuid.NewString()[:8]
	w := Workload{
		TeamID:      teamID,
		SandboxID:   sandboxID,
		ExecutionID: executionID,
		HasIAM:      true,
	}
	wantSPIFFE := fmt.Sprintf("spiffe://e2b.local/ns/%s/sbx/%s/exec/%s", teamID, sandboxID, executionID)
	authority := e2eGuestHost + ":80"

	errCh := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err

			return
		}
		errCh <- client.Handle(ctx, conn, w, authority, 0)
	}()

	_, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)

	url := fmt.Sprintf("http://127.0.0.1:%s%s", port, e2eGuestPath)
	out, err := dockerSandboxPOST(ctx, url, sandboxID)
	require.NoError(t, err, "sandbox container request: %s", out)
	require.Contains(t, out, "ok: request captured")

	select {
	case err := <-errCh:
		if err != nil {
			t.Logf("tunnel closed: %v", err)
		}
	case <-time.After(5 * time.Second):
	}

	time.Sleep(200 * time.Millisecond)

	captureLogs := composeLogs(t, mockRoot, "capture")
	require.Contains(t, captureLogs, "POST "+e2eGuestPath)
	require.Contains(t, captureLogs, e2eMarker)
	require.Contains(t, captureLogs, "Host: "+e2eGuestHost)
	require.Contains(t, captureLogs, "X-Sandbox-Id: "+sandboxID)

	require.Eventually(t, func() bool {
		return strings.Contains(filterLines(composeLogs(t, mockRoot, "envoy"), "hbone_connect"), wantSPIFFE)
	}, 5*time.Second, 200*time.Millisecond, "envoy access log SPIFFE %s", wantSPIFFE)
}

func dockerSandboxPOST(ctx context.Context, url, sandboxID string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "--network=host",
		"--name", "hbone-e2e-sandbox-"+uuid.NewString()[:8],
		"alpine:3.20",
		"wget", "-qO-", "-T", "10",
		"--post-data="+e2eMarker,
		"--header=Host: "+e2eGuestHost,
		"--header=X-E2E: sandbox-hbone",
		"--header=X-Sandbox-Id: "+sandboxID,
		"--header=Content-Type: text/plain",
		url,
	)
	out, err := cmd.CombinedOutput()

	return strings.TrimSpace(string(out)), err
}

func findMockRoot(t *testing.T) string {
	t.Helper()
	if v := os.Getenv("HBONE_MOCK_ROOT"); v != "" {
		return v
	}
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	candidates := []string{
		filepath.Join(filepath.Dir(file), "..", "..", "dev", "egresstunnel"),
		"dev/egresstunnel",
	}
	for _, root := range candidates {
		if st, err := os.Stat(filepath.Join(root, "docker-compose.yml")); err == nil && !st.IsDir() {
			return root
		}
	}
	t.Fatal("cannot find dev/egresstunnel (set HBONE_MOCK_ROOT)")

	return ""
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
	cmd := exec.Command("docker", "compose", "-f", filepath.Join(root, "docker-compose.yml"), "logs", "--no-color", "--since=2m", service)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "compose logs %s: %s", service, out)

	return string(out)
}

func filterLines(logs, needle string) string {
	var b strings.Builder
	for line := range strings.SplitSeq(logs, "\n") {
		if strings.Contains(line, needle) {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}

	return b.String()
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
