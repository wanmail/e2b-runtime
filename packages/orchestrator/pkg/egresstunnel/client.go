package egresstunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"go.uber.org/zap"

	"github.com/e2b-dev/infra/packages/shared/pkg/featureflags"
	"github.com/e2b-dev/infra/packages/shared/pkg/logger"
)

const (
	defaultDialTimeout = 10 * time.Second
)

// Workload is the sandbox identity the tunnel needs without importing the linux-only sandbox package.
type Workload struct {
	TeamID      string
	SandboxID   string
	ExecutionID string
	HasIAM      bool
	IsBuild     bool
}

// Config is the node-side HBONE client configuration.
type Config struct {
	GatewayAddr string
	TrustDomain string
	GatewayCA   string
	DialTimeout time.Duration
	ServerName  string
	RootCAs     *x509.CertPool
	Signer      *Signer
}

// Client opens HTTP/2 CONNECT tunnels to a platform Envoy with a per-execution client cert.
type Client struct {
	cfg    Config
	flags  *featureflags.Client
	logger logger.Logger
	pool   *connPool
}

// New constructs a Client. Signer must be set on cfg.
func New(cfg Config, flags *featureflags.Client, log logger.Logger) (*Client, error) {
	if cfg.GatewayAddr == "" {
		return nil, errors.New("egress gateway address is empty")
	}
	if cfg.TrustDomain == "" {
		cfg.TrustDomain = "e2b.local"
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = defaultDialTimeout
	}

	signer := cfg.Signer
	if signer == nil {
		return nil, errors.New("tunnel CA signer is required")
	}

	if cfg.ServerName == "" {
		host, _, err := net.SplitHostPort(cfg.GatewayAddr)
		if err != nil {
			host = cfg.GatewayAddr
		}
		cfg.ServerName = host
	}

	roots := cfg.RootCAs
	if roots == nil && cfg.GatewayCA != "" {
		pem, err := os.ReadFile(cfg.GatewayCA)
		if err != nil {
			return nil, fmt.Errorf("read EGRESS_GATEWAY_CA_CERT: %w", err)
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return nil, errors.New("EGRESS_GATEWAY_CA_CERT: no certificates")
		}
	}

	cfg.RootCAs = roots
	cfg.Signer = signer

	return &Client{
		cfg:    cfg,
		flags:  flags,
		logger: log,
		pool:   newConnPool(cfg),
	}, nil
}

// ShouldTunnel reports whether this workload's egress must go through the gateway.
func (c *Client) ShouldTunnel(ctx context.Context, w Workload) bool {
	if c == nil {
		return false
	}
	if !w.HasIAM || w.IsBuild {
		return false
	}
	if w.TeamID == "" || w.SandboxID == "" || w.ExecutionID == "" {
		return false
	}
	if c.flags == nil {
		return false
	}

	return c.flags.BoolFlag(ctx, featureflags.EgressHBONETunnelFlag,
		featureflags.TeamContext(w.TeamID),
		featureflags.SandboxContext(w.SandboxID),
	)
}

// Handle splices guest into an HTTP/2 CONNECT stream. Fail-closed: the guest
// connection is closed on error. Caller must not DialProxy afterwards.
func (c *Client) Handle(ctx context.Context, guest net.Conn, w Workload, authority string, tos int) error {
	defer guest.Close()

	if authority == "" {
		return errors.New("CONNECT authority is empty")
	}

	spiffeID, err := ID(c.cfg.TrustDomain, w.TeamID, w.SandboxID, w.ExecutionID)
	if err != nil {
		return err
	}

	stream, err := c.pool.connect(ctx, w.ExecutionID, spiffeID, authority, tos)
	if err != nil {
		c.logger.Error(ctx, "egress HBONE CONNECT failed",
			logger.WithSandboxID(w.SandboxID),
			logger.WithExecutionID(w.ExecutionID),
			zap.String("authority", authority),
			zap.Error(err),
		)

		return err
	}
	defer stream.Close()

	return splice(guest, stream)
}

// Forget drops the pooled HTTP/2 connection and cached leaf for an execution.
func (c *Client) Forget(executionID string) {
	if c == nil {
		return
	}
	c.pool.forget(executionID)
}

// Close tears down all pooled gateway connections.
func (c *Client) Close() error {
	if c == nil {
		return nil
	}

	return c.pool.closeAll()
}

func clientTLSConfig(cfg Config, spiffeID string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2"},
		ServerName: cfg.ServerName,
		RootCAs:    cfg.RootCAs,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return cfg.Signer.Certificate(spiffeID)
		},
	}
}
