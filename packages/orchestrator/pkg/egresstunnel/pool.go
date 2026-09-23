package egresstunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall"

	"golang.org/x/net/http2"
)

type connPool struct {
	cfg Config

	mu   sync.Mutex
	sess map[string]*session
}

type session struct {
	cc      *http2.ClientConn
	tlsConn *tls.Conn
}

func newConnPool(cfg Config) *connPool {
	return &connPool{
		cfg:  cfg,
		sess: make(map[string]*session),
	}
}

func (p *connPool) connect(ctx context.Context, executionID, spiffeID, authority string, tos int) (net.Conn, error) {
	if p.cfg.DialMode == DialModeHTTPS {
		return p.dialHTTPS(ctx, spiffeID, authority, tos)
	}

	s, err := p.session(ctx, executionID, spiffeID, tos)
	if err != nil {
		return nil, err
	}

	return s.openCONNECT(ctx, authority)
}

func (p *connPool) dialHTTPS(ctx context.Context, spiffeID, authority string, tos int) (net.Conn, error) {
	serverName := authorityHost(authority)
	if serverName == "" {
		return nil, errors.New("https dial: empty authority host for SNI")
	}

	dialer := &net.Dialer{
		Timeout: p.cfg.DialTimeout,
		Control: func(_, _ string, rawConn syscall.RawConn) error {
			return markDSCP(rawConn, tos)
		},
	}
	raw, err := dialer.DialContext(ctx, "tcp", p.cfg.GatewayAddr)
	if err != nil {
		return nil, fmt.Errorf("dial gateway: %w", err)
	}

	// HTTP/1.1 only: guest plaintext HTTP is spliced onto the TLS conn.
	// Offering h2 as well would let the peer pick h2 and break splice.
	tlsConn := tls.Client(raw, clientTLSConfig(p.cfg, spiffeID, serverName, []string{"http/1.1"}))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()

		return nil, fmt.Errorf("gateway tls: %w", err)
	}

	return tlsConn, nil
}

func authorityHost(authority string) string {
	host := authority
	if h, _, err := net.SplitHostPort(authority); err == nil {
		host = h
	}

	return host
}

func (p *connPool) session(ctx context.Context, executionID, spiffeID string, tos int) (*session, error) {
	p.mu.Lock()
	if s, ok := p.sess[executionID]; ok && s.cc.CanTakeNewRequest() {
		p.mu.Unlock()

		return s, nil
	}
	p.mu.Unlock()

	s, err := p.dial(ctx, spiffeID, tos)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	if existing, ok := p.sess[executionID]; ok && existing.cc.CanTakeNewRequest() {
		p.mu.Unlock()
		s.close()

		return existing, nil
	}
	if old, ok := p.sess[executionID]; ok {
		old.close()
	}
	p.sess[executionID] = s
	p.mu.Unlock()

	return s, nil
}

func (p *connPool) dial(ctx context.Context, spiffeID string, tos int) (*session, error) {
	dialer := &net.Dialer{
		Timeout: p.cfg.DialTimeout,
		Control: func(_, _ string, rawConn syscall.RawConn) error {
			return markDSCP(rawConn, tos)
		},
	}

	raw, err := dialer.DialContext(ctx, "tcp", p.cfg.GatewayAddr)
	if err != nil {
		return nil, fmt.Errorf("dial gateway: %w", err)
	}

	tlsConn := tls.Client(raw, clientTLSConfig(p.cfg, spiffeID, p.cfg.ServerName, []string{"h2"}))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		raw.Close()

		return nil, fmt.Errorf("gateway tls: %w", err)
	}
	if tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
		tlsConn.Close()

		return nil, fmt.Errorf("gateway ALPN is %q, want h2", tlsConn.ConnectionState().NegotiatedProtocol)
	}

	tr := &http2.Transport{}
	cc, err := tr.NewClientConn(tlsConn)
	if err != nil {
		tlsConn.Close()

		return nil, fmt.Errorf("http2 client: %w", err)
	}

	return &session{cc: cc, tlsConn: tlsConn}, nil
}

func (p *connPool) forget(executionID string) {
	p.mu.Lock()
	s, ok := p.sess[executionID]
	delete(p.sess, executionID)
	p.mu.Unlock()
	if ok {
		s.close()
	}
}

func (p *connPool) closeAll() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	var errs []error
	for id, s := range p.sess {
		delete(p.sess, id)
		if err := s.close(); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

func (s *session) close() error {
	if s == nil {
		return nil
	}
	if s.cc != nil {
		s.cc.Close()
	}
	if s.tlsConn != nil {
		return s.tlsConn.Close()
	}

	return nil
}

func markDSCP(c syscall.RawConn, tos int) error {
	if tos == 0 {
		return nil
	}

	var sockErr error
	err := c.Control(func(fd uintptr) {
		v4Err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TOS, tos)
		v6Err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS, tos)
		if v4Err != nil && v6Err != nil {
			sockErr = fmt.Errorf("setsockopt IP_TOS / IPV6_TCLASS both failed: %w", errors.Join(v4Err, v6Err))
		}
	})
	if err != nil {
		return err
	}

	return sockErr
}

func splice(a, b net.Conn) error {
	errc := make(chan error, 2)
	copy := func(dst, src net.Conn) {
		_, err := io.Copy(dst, src)
		errc <- err
		_ = dst.Close()
	}
	go copy(a, b)
	go copy(b, a)

	err := <-errc
	_ = a.Close()
	_ = b.Close()
	<-errc

	if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
		return err
	}

	return nil
}
