package core

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/kgretzky/evilginx2/log"

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

// GetFingerprintName returns the canonical name for a supported uTLS
// ClientHelloID. It is used for logging and transport caching.
func GetFingerprintName(id utls.ClientHelloID) string {
	switch id {
	case utls.HelloChrome_Auto:
		return "chrome"
	case utls.HelloFirefox_Auto:
		return "firefox"
	case utls.HelloSafari_Auto:
		return "safari"
	case utls.HelloEdge_Auto:
		return "edge"
	case utls.HelloIOS_Auto:
		return "ios"
	case utls.HelloRandomized:
		return "random"
	default:
		return "unknown"
	}
}

// ParseUserAgentFingerprint maps a User-Agent string to the uTLS fingerprint
// that best matches the browser it represents. This reduces JA3/UA mismatch
// when ja3_fingerprint is set to "auto".
func ParseUserAgentFingerprint(ua string) utls.ClientHelloID {
	l := strings.ToLower(ua)

	switch {
	case strings.Contains(l, "edg/") || strings.Contains(l, "edgios/") || strings.Contains(l, "edga/"):
		return utls.HelloEdge_Auto
	case strings.Contains(l, "firefox") && !strings.Contains(l, "seamonkey"):
		return utls.HelloFirefox_Auto
	case strings.Contains(l, "iphone"), strings.Contains(l, "ipad"), strings.Contains(l, "ipod"):
		return utls.HelloIOS_Auto
	case strings.Contains(l, "chrome"), strings.Contains(l, "chromium"), strings.Contains(l, "crios"):
		return utls.HelloChrome_Auto
	case strings.Contains(l, "safari"):
		return utls.HelloSafari_Auto
	default:
		return utls.HelloChrome_Auto
	}
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
		log.Debug("utls: dialing %s with fingerprint %v", addr, helloID)

		rawConn, err := baseDial(ctx, network, addr)
		if err != nil {
			log.Debug("utls: base dial to %s failed: %v", addr, err)
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

		// uTLS presets are applied lazily during HandshakeContext. Build the
		// ClientHello state explicitly so we can inspect and modify extensions
		// before the handshake goes on the wire.
		if err := uConn.BuildHandshakeState(); err != nil {
			log.Debug("utls: build handshake state for %s failed: %v", addr, err)
			rawConn.Close()
			return nil, err
		}

		// Browser presets (HelloChrome_Auto, HelloFirefox_Auto, etc.) hardcode
		// ALPN protocols ["h2", "http/1.1"]. goproxy's http.Transport cannot
		// detect a *utls.UConn as TLS and therefore does not upgrade to HTTP/2,
		// so an upstream server that negotiates h2 sends HTTP/2 frames that the
		// HTTP/1.x transport interprets as malformed. Replace the ALPN extension
		// with http/1.1 only to force the upstream response to stay HTTP/1.x.
		// The ALPN extension (id 16) is still present, so the JA3 fingerprint is
		// preserved.
		alpnFound := false
		for i, ext := range uConn.Extensions {
			if alpn, ok := ext.(*utls.ALPNExtension); ok {
				log.Debug("utls: overriding ALPN for %s from %v to [http/1.1]", addr, alpn.AlpnProtocols)
				uConn.Extensions[i] = &utls.ALPNExtension{
					AlpnProtocols: []string{"http/1.1"},
				}
				alpnFound = true
			}
		}
		if !alpnFound {
			log.Warning("utls: no ALPN extension found for %s, cannot restrict to HTTP/1.1", addr)
		}

		if err := uConn.HandshakeContext(ctx); err != nil {
			log.Debug("utls: handshake with %s failed: %v", addr, err)
			rawConn.Close()
			return nil, err
		}

		state := uConn.ConnectionState()
		log.Debug("utls: handshake complete with %s version=0x%x alpn=%q", addr, state.Version, state.NegotiatedProtocol)

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
