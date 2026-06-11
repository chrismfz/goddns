// Package proxy is the optional reverse-proxy mode: a TLS listener that
// routes by Host to internal upstreams (iDRAC/BMC consoles, switches —
// services that could never have a proper hostname + certificate on their
// own). The routing table comes from the [proxy."host"] sections of
// goddns.conf and is hot-swapped on config reload, like everything else.
package proxy

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/chrismfz/goddns/internal/config"
)

type rule struct {
	host    string
	allow   []*net.IPNet
	limit   *limiter // nil = unlimited
	handler http.Handler
}

// Proxy routes requests by Host header. Zero value is unusable; use New.
type Proxy struct {
	rules atomic.Pointer[map[string]*rule]
}

func New() *Proxy {
	p := &Proxy{}
	empty := map[string]*rule{}
	p.rules.Store(&empty)
	return p
}

// Update compiles the routing table from a validated config and swaps it in
// atomically. On error the previous table stays live.
func (p *Proxy) Update(cfg *config.Config) error {
	table := make(map[string]*rule, len(cfg.Proxy))
	for host, pr := range cfg.Proxy {
		r, err := compile(host, pr)
		if err != nil {
			return err
		}
		table[host] = r
	}
	p.rules.Store(&table)
	return nil
}

func compile(host string, pr config.ProxyRule) (*rule, error) {
	u, err := url.Parse(pr.Upstream)
	if err != nil {
		return nil, fmt.Errorf("proxy %s: %w", host, err)
	}

	rp := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(u) // also rewrites the outbound Host to the upstream's
			r.SetXForwarded()
			if pr.PreserveHost {
				r.Out.Host = r.In.Host
			}
		},
		Transport: &http.Transport{
			// BMC web stacks are universally self-signed; verification is
			// opt-in via upstream_verify.
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: !pr.UpstreamVerify, // #nosec G402
				MinVersion:         tls.VersionTLS10,   // ancient BMCs
			},
			Proxy:                 http.ProxyFromEnvironment,
			ForceAttemptHTTP2:     false,
			MaxIdleConns:          16,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 60 * time.Second,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("proxy %s -> %s: %v", host, pr.Upstream, err)
			http.Error(w, "upstream error", http.StatusBadGateway)
		},
		FlushInterval: 100 * time.Millisecond, // console streams
	}

	cr := &rule{host: host, handler: rp}
	for _, cidr := range pr.Allow {
		_, n, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			return nil, fmt.Errorf("proxy %s: allow %q: %w", host, cidr, err)
		}
		cr.allow = append(cr.allow, n)
	}
	if len(cr.allow) == 0 {
		log.Printf("proxy %s: no 'allow' list — open to the whole internet; "+
			"set allow=[...] if the upstream is a BMC/console", host)
	}
	if pr.RateLimit > 0 {
		cr.limit = newLimiter(pr.RateLimit)
	}
	return cr, nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	peerStr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peerStr = r.RemoteAddr
	}
	peer := net.ParseIP(peerStr)

	host := strings.ToLower(r.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	lw := &logWriter{ResponseWriter: w}
	defer func() {
		// One access-log line per request, nginx-ish:
		// proxy-access host peer "METHOD /path" status bytes duration
		log.Printf("proxy-access %s %s \"%s %s\" %d %dB %s",
			host, peerStr, r.Method, r.URL.RequestURI(),
			lw.status, lw.bytes, time.Since(start).Round(time.Millisecond))
	}()

	table := *p.rules.Load()
	rl, ok := table[host]
	if !ok {
		http.Error(lw, "unknown host", http.StatusNotFound)
		return
	}
	if len(rl.allow) > 0 {
		allowed := false
		for _, n := range rl.allow {
			if peer != nil && n.Contains(peer) {
				allowed = true
				break
			}
		}
		if !allowed {
			http.Error(lw, "forbidden", http.StatusForbidden)
			return
		}
	}
	if rl.limit != nil && peer != nil && !rl.limit.allow(peer) {
		http.Error(lw, "rate limited", http.StatusTooManyRequests)
		return
	}
	rl.handler.ServeHTTP(lw, r)
}

// logWriter captures status/bytes for the access log while passing through
// Flusher (streaming) and Hijacker (websocket upgrades for BMC consoles).
type logWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (l *logWriter) WriteHeader(code int) {
	if l.status == 0 {
		l.status = code
	}
	l.ResponseWriter.WriteHeader(code)
}

func (l *logWriter) Write(b []byte) (int, error) {
	if l.status == 0 {
		l.status = http.StatusOK
	}
	n, err := l.ResponseWriter.Write(b)
	l.bytes += int64(n)
	return n, err
}

func (l *logWriter) Flush() {
	if f, ok := l.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (l *logWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := l.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("hijack not supported")
	}
	if l.status == 0 {
		l.status = http.StatusSwitchingProtocols
	}
	return h.Hijack()
}

// RedirectHandler serves the optional plain-HTTP listener: permanent
// redirect of every known host to its HTTPS counterpart.
func (p *Proxy) RedirectHandler(httpsPort string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(r.Host)
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if _, ok := (*p.rules.Load())[host]; !ok {
			http.Error(w, "unknown host", http.StatusNotFound)
			return
		}
		target := "https://" + host
		if httpsPort != "" && httpsPort != "443" {
			target += ":" + httpsPort
		}
		http.Redirect(w, r, target+r.URL.RequestURI(), http.StatusPermanentRedirect)
	})
}
