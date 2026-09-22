// Local smoke: egresstunnel client → Envoy CONNECT (mTLS) → capture backend.
//
// Prerequisites (from packages/orchestrator/dev/egresstunnel):
//
//	./certs/gen.sh && docker compose up --build -d
//
// Run from packages/orchestrator:
//
//	go run ./cmd/hbone-smoke
package main

import (
	"bufio"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/e2b-dev/infra/packages/orchestrator/pkg/egresstunnel"
	"github.com/e2b-dev/infra/packages/shared/pkg/logger"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	root, err := findMockRoot()
	if err != nil {
		fatal(err)
	}

	caPath := filepath.Join(root, "certs", "tunnel-ca.crt")
	keyPath := filepath.Join(root, "certs", "tunnel-ca.key")
	gwCAPath := filepath.Join(root, "certs", "gateway-ca.crt")

	signer, err := egresstunnel.LoadSigner(caPath, keyPath)
	if err != nil {
		fatal(err)
	}

	gwPEM, err := os.ReadFile(gwCAPath)
	if err != nil {
		fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(gwPEM) {
		fatal(fmt.Errorf("no certs in %s", gwCAPath))
	}

	gateway := envOr("EGRESS_GATEWAY_ADDR", "127.0.0.1:15008")
	client, err := egresstunnel.New(egresstunnel.Config{
		GatewayAddr: gateway,
		TrustDomain: envOr("EGRESS_SPIFFE_TRUST_DOMAIN", "e2b.local"),
		ServerName:  envOr("EGRESS_GATEWAY_SERVER_NAME", "localhost"),
		RootCAs:     roots,
		Signer:      signer,
		DialTimeout: 5 * time.Second,
	}, nil, logger.L())
	if err != nil {
		fatal(err)
	}
	defer client.Close()

	w := egresstunnel.Workload{
		TeamID:      envOr("SMOKE_TEAM_ID", "team-smoke"),
		SandboxID:   envOr("SMOKE_SANDBOX_ID", "sbx-smoke"),
		ExecutionID: envOr("SMOKE_EXECUTION_ID", "exec-smoke"),
		HasIAM:      true,
	}
	// Authority is the *guest destination*. Envoy mock ignores it for
	// routing and always forwards to the capture cluster.
	authority := envOr("SMOKE_AUTHORITY", "api.example.com:443")

	guest, local := net.Pipe()
	errCh := make(chan error, 1)
	go func() {
		errCh <- client.Handle(ctx, guest, w, authority, 0)
	}()

	req := "" +
		"POST /hbone-smoke HTTP/1.1\r\n" +
		"Host: api.example.com\r\n" +
		"Content-Type: text/plain\r\n" +
		"Content-Length: 19\r\n" +
		"X-Smoke: egresstunnel\r\n" +
		"\r\n" +
		"hello from sandbox\n"

	if err := local.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		fatal(err)
	}
	if _, err := io.WriteString(local, req); err != nil {
		fatal(fmt.Errorf("write request: %w", err))
	}

	br := bufio.NewReader(local)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		fatal(fmt.Errorf("read status: %w", err))
	}
	fmt.Printf("status: %s", statusLine)
	if !strings.HasPrefix(statusLine, "HTTP/1.1 200") && !strings.HasPrefix(statusLine, "HTTP/1.0 200") {
		_ = local.Close()
		fatal(fmt.Errorf("expected 200, got %q", strings.TrimSpace(statusLine)))
	}

	headers := make(map[string]string)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			fatal(err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, ":")
		if ok {
			headers[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	fmt.Printf("x-captured-path: %s\n", headers["x-captured-path"])

	_ = local.Close()
	select {
	case err := <-errCh:
		if err != nil {
			fmt.Printf("tunnel closed: %v\n", err)
		}
	case <-time.After(3 * time.Second):
	}

	fmt.Println("OK: CONNECT+mTLS tunnel delivered the full HTTP request to capture via Envoy")
	fmt.Printf("    SPIFFE expected: spiffe://e2b.local/ns/%s/sbx/%s/exec/%s\n",
		w.TeamID, w.SandboxID, w.ExecutionID)
	fmt.Println("    check: docker compose -f", filepath.Join(root, "docker-compose.yml"), "logs envoy capture")
}

func findMockRoot() (string, error) {
	if v := os.Getenv("HBONE_MOCK_ROOT"); v != "" {
		return v, nil
	}
	candidates := []string{
		"dev/egresstunnel",
		"packages/orchestrator/dev/egresstunnel",
		filepath.Join("..", "dev", "egresstunnel"),
	}
	wd, _ := os.Getwd()
	for _, c := range candidates {
		p := c
		if !filepath.IsAbs(p) {
			p = filepath.Join(wd, c)
		}
		if st, err := os.Stat(filepath.Join(p, "docker-compose.yml")); err == nil && !st.IsDir() {
			return p, nil
		}
	}

	return "", fmt.Errorf("cannot find dev/egresstunnel (set HBONE_MOCK_ROOT)")
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}

	return def
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "hbone-smoke: %v\n", err)
	os.Exit(1)
}
