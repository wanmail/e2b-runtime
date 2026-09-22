package egresstunnel

import (
	"fmt"
	"net"
)

// Authority is the HTTP/2 CONNECT :authority — guest destination, not the gateway.
func Authority(hostname string, ip net.IP, port int) string {
	host := hostname
	if host == "" {
		if ip == nil {
			return ""
		}
		host = ip.String()
	}

	return net.JoinHostPort(host, fmt.Sprintf("%d", port))
}
