// Package egresssocks dials a SOCKS5 proxy (RFC 1928 / RFC 1929) for sandbox
// egress after the L4 firewall has allowed the flow.
//
// Identity is the username and password the control plane stored on the
// sandbox (network.egressProxy). This path does not mint or present a
// workload identity.
package egresssocks

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	version5       = 0x05
	cmdConnect     = 0x01
	methodNone     = 0x00
	methodUserPass = 0x02
	methodNoAccept = 0xff
	atypIPv4       = 0x01
	atypDomain     = 0x03
	atypIPv6       = 0x04
	authVersion    = 0x01
	repSuccess     = 0x00
)

// Config is one sandbox's SOCKS5 egress proxy.
type Config struct {
	ProxyAddr string
	Username  string
	Password  string
	// DialTimeout bounds the TCP dial to the proxy. Zero means 10s.
	DialTimeout time.Duration
}

// Target is the guest destination. Domain destinations are sent as
// ATYP=domain so the proxy resolves them (cloud BYOP remote DNS). An empty
// host or an IP-literal host is sent as the original destination IP.
type Target struct {
	Host   string
	IP     net.IP
	Port   int
	Domain bool
}

// TargetFrom classifies a peeked hostname the way Cloud BYOP does.
// ATYP=domain only when the flow was allowed by a domain rule and the
// hostname is not an IP literal. IP literals (including a numeric Host)
// and CIDR-only matches are sent as the original destination IP.
func TargetFrom(hostname string, ip net.IP, port int, domainMatch bool) Target {
	if domainMatch && hostname != "" && net.ParseIP(hostname) == nil {
		return Target{Host: hostname, Port: port, Domain: true}
	}

	return Target{IP: ip, Port: port}
}

// Dial opens a TCP connection to the proxy, authenticates, and issues CONNECT.
// The returned conn carries the tunneled byte stream. Fail closed: any
// handshake error closes the proxy connection and returns an error.
func Dial(ctx context.Context, cfg Config, target Target) (net.Conn, error) {
	if cfg.ProxyAddr == "" {
		return nil, errors.New("socks5 proxy address is empty")
	}
	if target.Port <= 0 || target.Port > 65535 {
		return nil, fmt.Errorf("socks5 destination port %d out of range", target.Port)
	}
	if !target.Domain && (target.IP == nil || target.IP.To4() == nil && target.IP.To16() == nil) {
		return nil, errors.New("socks5 IP destination is empty")
	}
	if target.Domain && target.Host == "" {
		return nil, errors.New("socks5 domain destination is empty")
	}

	timeout := cfg.DialTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	// Resolve the proxy on every dial and keep that TCP connection. A later
	// DNS change cannot retarget a handshake that is already in progress.
	dialer := &net.Dialer{Timeout: timeout}
	raw, err := dialer.DialContext(ctx, "tcp", cfg.ProxyAddr)
	if err != nil {
		return nil, fmt.Errorf("dial socks5 proxy: %w", err)
	}
	if err := handshake(raw, cfg, target); err != nil {
		_ = raw.Close()

		return nil, err
	}

	return raw, nil
}

func handshake(conn net.Conn, cfg Config, target Target) error {
	_ = conn.SetDeadline(time.Now().Add(cfg.DialTimeoutOr(10 * time.Second)))
	defer conn.SetDeadline(time.Time{})

	method := byte(methodNone)
	if cfg.Username != "" {
		method = methodUserPass
	}
	if _, err := conn.Write([]byte{version5, 0x01, method}); err != nil {
		return fmt.Errorf("socks5 greeting: %w", err)
	}
	var sel [2]byte
	if _, err := io.ReadFull(conn, sel[:]); err != nil {
		return fmt.Errorf("socks5 method: %w", err)
	}
	if sel[0] != version5 || sel[1] == methodNoAccept || sel[1] != method {
		return fmt.Errorf("socks5 method rejected: %d", sel[1])
	}
	if method == methodUserPass {
		if err := writeUserPass(conn, cfg.Username, cfg.Password); err != nil {
			return err
		}
	}
	if err := writeConnect(conn, target); err != nil {
		return err
	}

	return readConnectReply(conn)
}

// DialTimeoutOr returns DialTimeout or fallback when unset.
func (c Config) DialTimeoutOr(fallback time.Duration) time.Duration {
	if c.DialTimeout == 0 {
		return fallback
	}

	return c.DialTimeout
}

func writeUserPass(conn net.Conn, user, pass string) error {
	if len(user) > 255 || len(pass) > 255 {
		return errors.New("socks5 username or password exceeds 255 bytes")
	}
	buf := make([]byte, 0, 3+len(user)+len(pass))
	buf = append(buf, authVersion, byte(len(user)))
	buf = append(buf, user...)
	buf = append(buf, byte(len(pass)))
	buf = append(buf, pass...)
	if _, err := conn.Write(buf); err != nil {
		return fmt.Errorf("socks5 auth: %w", err)
	}
	var reply [2]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil {
		return fmt.Errorf("socks5 auth reply: %w", err)
	}
	if reply[0] != authVersion || reply[1] != 0x00 {
		return errors.New("socks5 authentication failed")
	}

	return nil
}

func writeConnect(conn net.Conn, target Target) error {
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(target.Port))

	var req []byte
	req = append(req, version5, cmdConnect, 0x00)
	if target.Domain {
		if len(target.Host) > 255 {
			return errors.New("socks5 domain longer than 255 bytes")
		}
		req = append(req, atypDomain, byte(len(target.Host)))
		req = append(req, target.Host...)
	} else if ip4 := target.IP.To4(); ip4 != nil {
		req = append(req, atypIPv4)
		req = append(req, ip4...)
	} else {
		req = append(req, atypIPv6)
		req = append(req, target.IP.To16()...)
	}
	req = append(req, port...)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks5 connect: %w", err)
	}

	return nil
}

func readConnectReply(conn net.Conn) error {
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return fmt.Errorf("socks5 connect reply: %w", err)
	}
	if hdr[0] != version5 {
		return fmt.Errorf("socks5 connect reply version %d", hdr[0])
	}
	if hdr[1] != repSuccess {
		return fmt.Errorf("socks5 connect refused: reply %d", hdr[1])
	}
	var rest int
	switch hdr[3] {
	case atypIPv4:
		rest = net.IPv4len + 2
	case atypIPv6:
		rest = net.IPv6len + 2
	case atypDomain:
		var n [1]byte
		if _, err := io.ReadFull(conn, n[:]); err != nil {
			return fmt.Errorf("socks5 bind domain: %w", err)
		}
		rest = int(n[0]) + 2
	default:
		return fmt.Errorf("socks5 bind atyp %d", hdr[3])
	}
	if _, err := io.CopyN(io.Discard, conn, int64(rest)); err != nil {
		return fmt.Errorf("socks5 bind addr: %w", err)
	}

	return nil
}
