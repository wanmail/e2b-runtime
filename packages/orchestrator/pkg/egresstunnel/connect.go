package egresstunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

func (s *session) openCONNECT(ctx context.Context, authority string) (net.Conn, error) {
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+authority, pr)
	if err != nil {
		_ = pw.Close()

		return nil, fmt.Errorf("CONNECT request: %w", err)
	}
	req.Host = authority
	req.ContentLength = -1

	type roundTrip struct {
		resp *http.Response
		err  error
	}
	ch := make(chan roundTrip, 1)
	go func() {
		resp, err := s.cc.RoundTrip(req)
		ch <- roundTrip{resp: resp, err: err}
	}()

	var rt roundTrip
	select {
	case rt = <-ch:
	case <-ctx.Done():
		_ = pw.Close()

		return nil, fmt.Errorf("CONNECT: %w", ctx.Err())
	}

	if rt.err != nil {
		_ = pw.Close()

		return nil, fmt.Errorf("CONNECT roundtrip: %w", rt.err)
	}
	if rt.resp.StatusCode != http.StatusOK {
		_ = pw.Close()
		_ = rt.resp.Body.Close()

		return nil, fmt.Errorf("CONNECT status %d", rt.resp.StatusCode)
	}

	return &tunnelConn{
		reader: rt.resp.Body,
		writer: pw,
	}, nil
}

type tunnelConn struct {
	reader io.ReadCloser
	writer io.WriteCloser
	once   sync.Once
}

func (c *tunnelConn) Read(p []byte) (int, error)  { return c.reader.Read(p) }
func (c *tunnelConn) Write(p []byte) (int, error) { return c.writer.Write(p) }

func (c *tunnelConn) Close() error {
	var err error
	c.once.Do(func() {
		err = errors.Join(c.writer.Close(), c.reader.Close())
	})

	return err
}

func (c *tunnelConn) LocalAddr() net.Addr                { return tunnelAddr{} }
func (c *tunnelConn) RemoteAddr() net.Addr               { return tunnelAddr{} }
func (c *tunnelConn) SetDeadline(time.Time) error        { return nil }
func (c *tunnelConn) SetReadDeadline(time.Time) error    { return nil }
func (c *tunnelConn) SetWriteDeadline(time.Time) error   { return nil }

type tunnelAddr struct{}

func (tunnelAddr) Network() string { return "hbone" }
func (tunnelAddr) String() string  { return "hbone" }
