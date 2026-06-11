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
	"reflect"
	"strings"
	"sync/atomic"
	"time"

	"github.com/chrismfz/goddns/internal/config"
)

type rule struct {
	host      string
	src       config.ProxyRule // for change detection across reloads
	allow     []*net.IPNet
	limit     *limiter // nil = unlimited
	transport *http.Transport
	handler   http.Handler
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
// atomically. Rules whose config is unchanged are carried over (keeping
// their limiter state and connection pool); replaced rules get their idle
// upstream connections closed. On error the previous table stays live.
func (p *Proxy) Update(cfg *config.Config) error {
	prev := *p.rules.Load()
	table := make(map[string]*rule, len(cfg.Proxy))
	for host, pr := range cfg.Proxy {
		if old, ok := prev[host]; ok && reflect.DeepEqual(old.src, pr) {
			table[host] = old
			continue
		}
		r, err := compile(host, pr)
		if err != nil {
			return err
		}
		table[host] = r
	}
	p.rules.Store(&table)
	for host, old := range prev {
		if table[host] != old {
			old.transport.CloseIdleConnections()
		}
	}
	return nil
}

func compile(host string, pr config.ProxyRule) (*rule, error) {
	u, err := url.Parse(pr.Upstream)
	if err != nil {
		return nil, fmt.Errorf("proxy %s: %w", host, err)
	}

	transport := &http.Transport{
		// BMC web stacks are universally self-signed; verification is
		// opt-in via upstream_verify.
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !pr.UpstreamVerify, // #nosec G402
			MinVersion:         tls.VersionTLS10,   // ancient BMCs
		},
		// No Proxy field: upstreams are internal by definition — never
		// route them through an HTTPS_PROXY from the environment.
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
	}

	rp := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(u) // also rewrites the outbound Host to the upstream's
			r.SetXForwarded()
			if pr.PreserveHost {
				r.Out.Host = r.In.Host
			}
			// The stdlib strips X-Forwarded-*/Forwarded, but ad-hoc
			// identity headers would pass through to the upstream, and
			// BMC audit logs love X-Real-IP. Never trust the client's.
			r.Out.Header.Del("X-Client-IP")
			r.Out.Header.Del("True-Client-IP")
			if peer, _, err := net.SplitHostPort(r.In.RemoteAddr); err == nil {
				r.Out.Header.Set("X-Real-IP", peer)
			} else {
				r.Out.Header.Del("X-Real-IP")
			}
		},
		Transport: transport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("proxy %s -> %s: %v", host, pr.Upstream, err)
			http.Error(w, "upstream error", http.StatusBadGateway)
		},
		FlushInterval: 100 * time.Millisecond, // console streams
	}

	cr := &rule{host: host, src: pr, transport: transport, handler: rp}
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

// hostKey normalises an inbound Host header the same way config.Load
// normalises table keys: lowercase, no port, no trailing dot.
func hostKey(h string) string {
	h = strings.ToLower(h)
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	return strings.TrimSuffix(h, ".")
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	peerStr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peerStr = r.RemoteAddr
	}
	peer := net.ParseIP(peerStr)
	host := hostKey(r.Host)

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
	if rl.limit != nil && !rl.limit.allow(peer) {
		http.Error(lw, "rate limited", http.StatusTooManyRequests)
		return
	}
	rl.handler.ServeHTTP(lw, r)
}

// RedirectHandler serves the optional plain-HTTP listener: redirect of
// every known host to its HTTPS counterpart. 307 + no-store so a stale
// mapping is never cached into clients permanently.
func (p *Proxy) RedirectHandler(httpsPort string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := hostKey(r.Host)
		if _, ok := (*p.rules.Load())[host]; !ok {
			http.Error(w, "unknown host", http.StatusNotFound)
			return
		}
		target := "https://" + host
		if httpsPort != "" && httpsPort != "443" {
			target += ":" + httpsPort
		}
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, target+r.URL.RequestURI(), http.StatusTemporaryRedirect)
	})
}

// logWriter captures status/bytes for the access log while passing through
// Flusher (streaming) and Hijacker (websocket upgrades for BMC consoles).
// Bytes after a hijack are not counted: console sessions log as 101/0B.
type logWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (l *logWriter) Unwrap() http.ResponseWriter { return l.ResponseWriter }

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
