package outbound

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"
)

var blockedPrefixes = mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
	"192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
	"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "100::/64", "2001:db8::/32", "fc00::/7", "fe80::/10", "ff00::/8",
)

// ValidateHTTPS rejects destinations that resolve to non-public address space.
func ValidateHTTPS(ctx context.Context, raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil {
		return fmt.Errorf("destination must be an HTTPS URL without user information")
	}
	_, err = resolvePublic(ctx, parsed.Hostname())
	return err
}

func NewSafeHTTPClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:               nil,
		ForceAttemptHTTP2:   true,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 10 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, fmt.Errorf("invalid outbound address: %w", err)
			}
			resolved, err := resolvePublic(ctx, host)
			if err != nil {
				return nil, err
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(resolved.String(), port))
		},
	}
	return &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func resolvePublic(ctx context.Context, hostname string) (netip.Addr, error) {
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", hostname)
	if err != nil || len(addresses) == 0 {
		return netip.Addr{}, fmt.Errorf("destination cannot be resolved")
	}
	for _, raw := range addresses {
		address := raw.Unmap()
		if !address.IsValid() || !address.IsGlobalUnicast() || blockedAddress(address) {
			return netip.Addr{}, fmt.Errorf("destination resolves to non-public address space")
		}
	}
	return addresses[0].Unmap(), nil
}

func blockedAddress(address netip.Addr) bool {
	for _, prefix := range blockedPrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func mustPrefixes(values ...string) []netip.Prefix {
	result := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		result = append(result, netip.MustParsePrefix(value))
	}
	return result
}
