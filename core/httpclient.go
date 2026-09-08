package core

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

// SharedHTTPTransport is a globally reused HTTP transport with connection pooling.
// Reusing a single transport allows TCP connections to be kept alive and reused,
// dramatically reducing ephemeral port exhaustion and handshake overhead.
var SharedHTTPTransport = &http.Transport{
	MaxIdleConns:        100,
	MaxIdleConnsPerHost: 20,
	IdleConnTimeout:     90 * time.Second,
	TLSHandshakeTimeout: 10 * time.Second,
}

// UTLSFingerprints maps human-readable names to uTLS ClientHello presets.
// These presets mimic the TLS handshake of real browsers, making the JA3
// fingerprint of outbound requests match a legitimate client.
var UTLSFingerprints = map[string]utls.ClientHelloID{
	"chrome":  utls.HelloChrome_Auto,
	"firefox": utls.HelloFirefox_Auto,
	"safari":  utls.HelloSafari_Auto,
	"edge":    utls.HelloEdge_Auto,
	"ios":     utls.HelloIOS_Auto,
	"random":  utls.HelloRandomized,
}

// NewHTTPClient returns a new HTTP client sharing the global transport.
// Use this instead of &http.Client{} to benefit from connection pooling.
func NewHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: SharedHTTPTransport,
		Timeout:   timeout,
	}
}

// ParseUTLSFingerprint resolves a fingerprint name to a uTLS ClientHelloID.
// An empty name defaults to Chrome to preserve backwards compatibility.
func ParseUTLSFingerprint(name string) (utls.ClientHelloID, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return utls.HelloChrome_Auto, nil
	}
	if id, ok := UTLSFingerprints[name]; ok {
		return id, nil
	}
	return utls.ClientHelloID{}, fmt.Errorf("unknown JA3 fingerprint: %q (valid: chrome, firefox, safari, edge, ios, random)", name)
}

// UTLSFingerprintNames returns the list of supported fingerprint names.
func UTLSFingerprintNames() []string {
	names := make([]string, 0, len(UTLSFingerprints))
	for name := range UTLSFingerprints {
		names = append(names, name)
	}
	return names
}

// UTLSDialTLSContext returns a DialTLSContext function that performs TLS
// handshakes using a uTLS browser fingerprint. The optional baseDial is used
// to establish the underlying TCP connection so that upstream SOCKS5/HTTP
// proxies continue to work.
func UTLSDialTLSContext(helloID utls.ClientHelloID, baseDial func(ctx context.Context, network, addr string) (net.Conn, error)) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if baseDial == nil {
		baseDial = (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext
	}

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		rawConn, err := baseDial(ctx, network, addr)
		if err != nil {
			return nil, err
		}

		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}

		config := &utls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
		}

		uConn := utls.UClient(rawConn, config, helloID)

		// Browser presets (HelloChrome_Auto, HelloFirefox_Auto, etc.) hardcode
		// ALPN protocols ["h2", "http/1.1"]. goproxy's http.Transport cannot
		// detect a *utls.UConn as TLS and therefore does not upgrade to HTTP/2,
		// so an upstream server that negotiates h2 sends HTTP/2 frames that the
		// HTTP/1.x transport interprets as malformed. Replace the ALPN extension
		// with http/1.1 only to force the upstream response to stay HTTP/1.x.
		// The ALPN extension (id 16) is still present, so the JA3 fingerprint is
		// preserved.
		for i, ext := range uConn.Extensions {
			if _, ok := ext.(*utls.ALPNExtension); ok {
				uConn.Extensions[i] = &utls.ALPNExtension{
					AlpnProtocols: []string{"http/1.1"},
				}
			}
		}

		if err := uConn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, err
		}

		return uConn, nil
	}
}

// NewUTLSTransport returns an http.Transport that performs outbound TLS
// handshakes with a uTLS browser fingerprint instead of the Go standard
// library fingerprint. The optional baseDial is used to establish the
// underlying TCP connection, which allows upstream SOCKS5/HTTP proxies to
// remain functional.
func NewUTLSTransport(helloID utls.ClientHelloID, baseDial func(ctx context.Context, network, addr string) (net.Conn, error)) *http.Transport {
	return &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		DialContext:         baseDial,
		DialTLSContext:      UTLSDialTLSContext(helloID, baseDial),
	}
}

// NewUTLSHTTPClient returns an HTTP client that uses the specified uTLS
// fingerprint for outbound TLS connections.
func NewUTLSHTTPClient(timeout time.Duration, helloID utls.ClientHelloID) *http.Client {
	return &http.Client{
		Transport: NewUTLSTransport(helloID, nil),
		Timeout:   timeout,
	}
}
