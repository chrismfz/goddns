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

	"golang.org/x/crypto/bcrypt"

	"github.com/chrismfz/goddns/internal/config"
)

type rule struct {
	host      string
	src       config.ProxyRule // for change detection across reloads
	allow     []*net.IPNet
	users     map[string]string // basic auth: user -> bcrypt hash; empty = no auth
	limit     *limiter          // nil = unlimited
	transport *http.Transport
	handler   http.Handler
}

// Proxy routes requests by Host header. Zero value is unusable; use New.
type Proxy struct {
	rules atomic.Pointer[map[string]*rule]
	stats *stats
}

func New() *Proxy {
	p := &Proxy{stats: newStats()}
	empty := map[string]*rule{}
	p.rules.Store(&empty)
	return p
}

// Stats returns a per-host traffic snapshot (cumulative since start) for the
// admin dashboard.
func (p *Proxy) Stats() []HostStat { return p.stats.snapshot() }

// ValidHost reports whether h is a syntactically valid proxy vhost key: a
// lowercase hostname (labels of letters/digits/hyphens separated by dots, no
// port, no path, no trailing dot). This is also what makes h safe to use as a
// proxy.d/<host>.conf fragment filename — it can't contain a slash or "..".
func ValidHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// ValidateRule checks a proxy vhost is well-formed BEFORE it is written to a
// proxy.d/ fragment: a valid host, a parseable http(s) upstream with a host,
// valid allow CIDRs, and well-formed user:bcrypt basic_auth entries. It is
// deliberately stricter than the runtime loader (compile, which stays lenient
// for backward compatibility) so a bad value is rejected at write time rather
// than failing the next reload.
func ValidateRule(host string, pr config.ProxyRule) error {
	if !ValidHost(host) {
		return fmt.Errorf("invalid vhost %q: want a hostname (lowercase letters, digits, hyphens, dots; no port/path)", host)
	}
	u, err := url.Parse(strings.TrimSpace(pr.Upstream))
	if err != nil {
		return fmt.Errorf("upstream %q: %w", pr.Upstream, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("upstream %q: scheme must be http or https", pr.Upstream)
	}
	if u.Host == "" {
		return fmt.Errorf("upstream %q: missing host", pr.Upstream)
	}
	// The upstream is used as a host root; a path/query/userinfo/fragment would
	// land in the fragment verbatim and surprise at routing time. Reject them at
	// write time (a bare trailing "/" is fine).
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return fmt.Errorf("upstream %q: just scheme://host[:port], no path/query/credentials", pr.Upstream)
	}
	for _, cidr := range pr.Allow {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(cidr)); err != nil {
			return fmt.Errorf("allow %q: %w", cidr, err)
		}
	}
	for _, cred := range pr.BasicAuth {
		user, hash, ok := strings.Cut(cred, ":")
		if !ok || user == "" {
			return fmt.Errorf("basic_auth %q: want user:bcrypt-hash", cred)
		}
		if _, err := bcrypt.Cost([]byte(hash)); err != nil {
			return fmt.Errorf("basic_auth for %q: not a bcrypt hash (generate one with `goddns passwd`)", user)
		}
	}
	if pr.RateLimit < 0 {
		return fmt.Errorf("rate_limit must be >= 0")
	}
	return nil
}

// accessLogger optionally routes the per-request "proxy-access" lines to a
// dedicated logger (access_log in the config, nginx-style). nil = the
// process-wide logger, i.e. merged into the main log. Errors/warnings
// always stay on the main logger.
var accessLogger atomic.Pointer[log.Logger]

func SetAccessLogger(l *log.Logger) { accessLogger.Store(l) }

func alog() *log.Logger {
	if l := accessLogger.Load(); l != nil {
		return l
	}
	return log.Default()
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
	// Forget counters for hosts the reload removed, and seed a zero entry for
	// every configured host so the dashboard lists them immediately (at 0)
	// rather than hiding the whole panel until the first request lands.
	p.stats.prune(table)
	for host := range table {
		p.stats.host(host)
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
	if len(pr.BasicAuth) > 0 {
		cr.users = make(map[string]string, len(pr.BasicAuth))
		for _, cred := range pr.BasicAuth {
			user, hash, ok := strings.Cut(cred, ":")
			if !ok {
				return nil, fmt.Errorf("proxy %s: malformed basic_auth entry", host)
			}
			cr.users[user] = hash
		}
	}
	if len(cr.allow) == 0 && len(cr.users) == 0 {
		log.Printf("proxy %s: no 'allow' list and no basic_auth — open to the "+
			"whole internet; set at least one if the upstream is a BMC/console", host)
	}
	if pr.RateLimit > 0 {
		cr.limit = newLimiter(pr.RateLimit)
	}
	return cr, nil
}

// checkAuth validates Basic credentials against the rule's bcrypt entries.
func (rl *rule) checkAuth(r *http.Request) bool {
	user, pass, ok := r.BasicAuth()
	if !ok {
		return false
	}
	hash, ok := rl.users[user]
	if !ok {
		// Burn comparable time so usernames aren't probeable by timing.
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(pass))
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass)) == nil
}

// A valid bcrypt hash of nothing in particular, for constant-ish timing on
// unknown usernames.
var dummyHash = []byte("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy")

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
		alog().Printf("proxy-access %s %s \"%s %s\" %d %dB %s",
			host, peerStr, r.Method, r.URL.RequestURI(),
			lw.status, lw.bytes, time.Since(start).Round(time.Millisecond))
		// Per-host accounting (only for a known host; lw.stat stays nil for a
		// 404'd unknown host so random Host headers can't allocate counters).
		if lw.stat != nil {
			lw.stat.bytesOut.Add(lw.bytes) // post-hijack bytes are counted live via countConn
			lw.stat.note(lw.status)
		}
	}()

	table := *p.rules.Load()
	rl, ok := table[host]
	if !ok {
		http.Error(lw, "unknown host", http.StatusNotFound)
		return
	}

	// The host is real: start counting. Done before the allow/auth gates so
	// blocked traffic (403/401/429) is visible too, not just successful hits.
	c := p.stats.host(host)
	c.requests.Add(1)
	c.lastSeen.Store(start.Unix())
	c.active.Add(1)
	defer c.active.Add(-1)
	lw.stat = c
	r.Body = &countReadCloser{rc: r.Body, n: &c.bytesIn}
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
	// Rate limit BEFORE auth so credential brute force eats 429s.
	if rl.limit != nil && !rl.limit.allow(peer) {
		http.Error(lw, "rate limited", http.StatusTooManyRequests)
		return
	}
	if len(rl.users) > 0 && !rl.checkAuth(r) {
		lw.Header().Set("WWW-Authenticate", `Basic realm="goddns", charset="UTF-8"`)
		http.Error(lw, "authentication required", http.StatusUnauthorized)
		return
	}
	// Never leak the client's credentials to the upstream.
	if len(rl.users) > 0 {
		r.Header.Del("Authorization")
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
	stat   *counters // nil for an unknown host; set once the route is known
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
	hj, ok := l.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("hijack not supported")
	}
	if l.status == 0 {
		l.status = http.StatusSwitchingProtocols
	}
	conn, rw, err := hj.Hijack()
	if err != nil || l.stat == nil {
		return conn, rw, err
	}
	// Wrap the hijacked conn so a long-lived console/websocket session still
	// contributes its bytes to the per-host counters (the access log already
	// gives up at 101/0B here).
	return &countConn{Conn: conn, in: &l.stat.bytesIn, out: &l.stat.bytesOut}, rw, nil
}
