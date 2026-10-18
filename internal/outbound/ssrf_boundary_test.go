package outbound

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestSafeHTTPClientRejectsProtectedAddressesAtDial(t *testing.T) {
	client := NewSafeHTTPClient(time.Second)
	transport := client.Transport.(*http.Transport)
	defer transport.CloseIdleConnections()
	for _, host := range []string{
		"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.0.1",
		"169.254.169.254", "100.100.100.200", "0.0.0.0",
		"::1", "::ffff:127.0.0.1", "::ffff:169.254.169.254", "fc00::1", "fe80::1",
	} {
		t.Run(host, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			conn, err := transport.DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
			if conn != nil {
				conn.Close()
				t.Fatal("protected destination was dialed")
			}
			if err == nil || !strings.Contains(err.Error(), "non-public address space") {
				t.Fatalf("expected address-policy rejection, got %v", err)
			}
		})
	}
}

func TestSafeHTTPClientDisablesProxyAndRedirects(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	client := NewSafeHTTPClient(time.Second)
	transport := client.Transport.(*http.Transport)
	defer transport.CloseIdleConnections()
	if transport.Proxy != nil || transport.DialTLSContext != nil || transport.DialTLS != nil {
		t.Fatal("transport can bypass protected dialing through a proxy or custom TLS dialer")
	}
	request, err := http.NewRequest(http.MethodGet, "https://127.0.0.1/metadata", nil)
	if err != nil {
		t.Fatal(err)
	}
	if client.CheckRedirect == nil || !errors.Is(client.CheckRedirect(request, nil), http.ErrUseLastResponse) {
		t.Fatal("redirects are not disabled")
	}
	if transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("TLS certificate verification is disabled")
	}
}

func TestSafeHTTPClientRejectsDNSRebindingAfterValidation(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var private atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 4096)
		for {
			n, peer, err := server.ReadFrom(buffer)
			if err != nil {
				return
			}
			var query dnsmessage.Message
			if query.Unpack(buffer[:n]) != nil {
				continue
			}
			response := dnsmessage.Message{
				Header:    dnsmessage.Header{ID: query.ID, Response: true, Authoritative: true},
				Questions: query.Questions,
			}
			for _, question := range query.Questions {
				if question.Type != dnsmessage.TypeA {
					continue
				}
				ip := [4]byte{1, 1, 1, 1}
				if private.Load() {
					ip = [4]byte{127, 0, 0, 1}
				}
				response.Answers = append(response.Answers, dnsmessage.Resource{
					Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
					Body:   &dnsmessage.AResource{A: ip},
				})
			}
			packet, err := response.Pack()
			if err == nil {
				_, _ = server.WriteTo(packet, peer)
			}
		}
	}()
	original := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", server.LocalAddr().String())
	}}
	t.Cleanup(func() {
		net.DefaultResolver = original
		server.Close()
		<-done
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	const destination = "https://metadata.ssrf-boundary.test/client.json"
	if err := ValidateHTTPS(ctx, destination); err != nil {
		t.Fatalf("initial public DNS answer rejected: %v", err)
	}
	private.Store(true)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, destination, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := NewSafeHTTPClient(time.Second)
	defer client.CloseIdleConnections()
	response, err := client.Do(request)
	if response != nil {
		response.Body.Close()
		t.Fatal("request escaped rebinding protection")
	}
	if err == nil || !strings.Contains(err.Error(), "non-public address space") {
		t.Fatalf("expected dial-time rejection of changed DNS answer, got %v", err)
	}
}
