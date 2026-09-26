package egresssocks

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTargetFrom(t *testing.T) {
	t.Parallel()
	ip := net.ParseIP("203.0.113.10")
	dom := TargetFrom("api.github.com", ip, 443, true)
	require.True(t, dom.Domain)
	require.Equal(t, "api.github.com", dom.Host)

	// CIDR allow does not turn a peeked Host into remote DNS.
	cidr := TargetFrom("api.github.com", ip, 443, false)
	require.False(t, cidr.Domain)
	require.True(t, cidr.IP.Equal(ip))

	lit := TargetFrom("1.1.1.1", ip, 80, true)
	require.False(t, lit.Domain)
	require.True(t, lit.IP.Equal(ip))

	none := TargetFrom("", ip, 80, false)
	require.False(t, none.Domain)
}

func TestDialUserPassDomain(t *testing.T) {
	t.Parallel()
	ln := listenSOCKS(t, "sbx-1", "secret")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := Dial(ctx, Config{
		ProxyAddr: ln.Addr().String(),
		Username:  "sbx-1",
		Password:  "secret",
	}, Target{Host: "api.github.com", Port: 443, Domain: true})
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)
	buf := make([]byte, 4)
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	require.Equal(t, "pong", string(buf))
}

func TestDialRejectsBadPassword(t *testing.T) {
	t.Parallel()
	ln := listenSOCKS(t, "sbx-1", "secret")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := Dial(ctx, Config{
		ProxyAddr: ln.Addr().String(),
		Username:  "sbx-1",
		Password:  "nope",
	}, Target{Host: "api.github.com", Port: 80, Domain: true})
	require.Error(t, err)
}

func TestDialIPv4NoAuth(t *testing.T) {
	t.Parallel()
	ln := listenSOCKS(t, "", "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := Dial(ctx, Config{ProxyAddr: ln.Addr().String()}, Target{
		IP:   net.ParseIP("203.0.113.8"),
		Port: 80,
	})
	require.NoError(t, err)
	conn.Close()
}

// listenSOCKS is a minimal RFC 1928/1929 CONNECT sink that echoes "pong".
func listenSOCKS(t *testing.T, wantUser, wantPass string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveSOCKS(c, wantUser, wantPass)
		}
	}()

	return ln
}

func serveSOCKS(c net.Conn, wantUser, wantPass string) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	var greet [2]byte
	if _, err := io.ReadFull(c, greet[:]); err != nil || greet[0] != 0x05 {
		return
	}
	methods := make([]byte, greet[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	method := byte(0x00)
	if wantUser != "" {
		method = 0x02
	}
	if _, err := c.Write([]byte{0x05, method}); err != nil {
		return
	}
	if method == 0x02 {
		var hdr [2]byte
		if _, err := io.ReadFull(c, hdr[:]); err != nil || hdr[0] != 0x01 {
			return
		}
		user := make([]byte, hdr[1])
		if _, err := io.ReadFull(c, user); err != nil {
			return
		}
		var plen [1]byte
		if _, err := io.ReadFull(c, plen[:]); err != nil {
			return
		}
		pass := make([]byte, plen[0])
		if _, err := io.ReadFull(c, pass); err != nil {
			return
		}
		status := byte(0x00)
		if string(user) != wantUser || string(pass) != wantPass {
			status = 0x01
		}
		_, _ = c.Write([]byte{0x01, status})
		if status != 0x00 {
			return
		}
	}
	var req [4]byte
	if _, err := io.ReadFull(c, req[:]); err != nil || req[1] != 0x01 {
		return
	}
	switch req[3] {
	case 0x01:
		_, _ = io.CopyN(io.Discard, c, 4+2)
	case 0x04:
		_, _ = io.CopyN(io.Discard, c, 16+2)
	case 0x03:
		var n [1]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			return
		}
		_, _ = io.CopyN(io.Discard, c, int64(n[0])+2)
	default:
		return
	}
	reply := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(reply[8:], 0)
	if _, err := c.Write(reply); err != nil {
		return
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil {
		return
	}
	_, _ = c.Write([]byte("pong"))
}
