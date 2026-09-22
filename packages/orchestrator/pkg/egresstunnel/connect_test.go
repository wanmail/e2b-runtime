package egresstunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"

	"github.com/e2b-dev/infra/packages/shared/pkg/logger"
)

func TestHandleCONNECTPresentsSPIFFE(t *testing.T) {
	t.Parallel()

	ca, caKey := mustTestCA(t)
	ip := net.ParseIP("127.0.0.1")
	serverCert := issueServerCert(t, ca, caKey, ip)

	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(ca)

	var (
		mu          sync.Mutex
		gotAuthority string
		gotSPIFFE    string
		gotCONNECT   = make(chan struct{})
	)

	mux := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "method", http.StatusMethodNotAllowed)

			return
		}
		mu.Lock()
		gotAuthority = r.Host
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 && len(r.TLS.PeerCertificates[0].URIs) > 0 {
			gotSPIFFE = r.TLS.PeerCertificates[0].URIs[0].String()
		}
		mu.Unlock()
		select {
		case <-gotCONNECT:
		default:
			close(gotCONNECT)
		}
		w.WriteHeader(http.StatusOK)
		// Keep the CONNECT stream open until the client tears down.
		<-r.Context().Done()
	})

	h2s := &http2.Server{}
	srv := &http.Server{
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{serverCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    clientCAs,
			NextProtos:   []string{"h2"},
		},
	}
	http2.ConfigureServer(srv, h2s)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", srv.TLSConfig)
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close(); _ = ln.Close() })
	go func() { _ = srv.Serve(ln) }()

	roots := x509.NewCertPool()
	roots.AddCert(ca)
	client, err := New(Config{
		GatewayAddr: ln.Addr().String(),
		TrustDomain: "e2b.local",
		ServerName:  "127.0.0.1",
		RootCAs:     roots,
		Signer:      NewSigner(ca, caKey),
		DialTimeout: 5 * time.Second,
	}, nil, logger.L())
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	guest, local := net.Pipe()
	t.Cleanup(func() { _ = guest.Close(); _ = local.Close() })

	w := Workload{TeamID: "team", SandboxID: "sandbox-1", ExecutionID: "exec-1", HasIAM: true}
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() {
		done <- client.Handle(ctx, guest, w, "api.example.com:443", 0)
	}()

	select {
	case <-gotCONNECT:
	case <-time.After(5 * time.Second):
		t.Fatal("CONNECT not received")
	}

	mu.Lock()
	assert.Equal(t, "api.example.com:443", gotAuthority)
	assert.Equal(t, "spiffe://e2b.local/ns/team/sbx/sandbox-1/exec/exec-1", gotSPIFFE)
	mu.Unlock()

	cancel()
	_ = local.Close()
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Handle did not return")
	}
}
