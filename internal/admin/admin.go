// Package admin is the optional built-in web UI: a read-only dashboard
// (DDNS records, proxy table, log tail) plus DDNS token CRUD. It is served
// as a vhost on the proxy listener and gated by, in order: a CIDR allowlist,
// an optional outer HTTP Basic gate, and a login session (signed cookie).
// It can rewrite DNS, so the layers are deliberate — see README.
package admin

import (
	"bufio"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/store"
)

const cookieName = "goddns_admin"

// Store is the slice of the token store the admin UI needs.
type Store interface {
	List() ([]store.Record, error)
	Add(name, zone string, ttl uint32) (store.Record, string, error)
	Del(name string) error
}

// Handler serves the admin UI. Construct with New.
type Handler struct {
	cfg     func() *config.Config // live config (admin auth + proxy table)
	store   Store
	secret  []byte
	version string
}

func New(cfg func() *config.Config, st Store, secret []byte, version string) *Handler {
	return &Handler{cfg: cfg, store: st, secret: secret, version: version}
}

func clientIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(host)
}

func (h *Handler) audit(user, peer, format string, a ...any) {
	log.Printf("admin-audit user=%s peer=%s "+format, append([]any{user, peer}, a...)...)
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ad := &h.cfg().Admin
	peer := clientIP(r)
	peerStr := "?"
	if peer != nil {
		peerStr = peer.String()
	}

	// Layer 1: CIDR allowlist (a real filter, not obscurity).
	if !ad.IsAllowed(peer) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// Layer 2: optional outer HTTP Basic gate — keeps scanners off the
	// login form entirely.
	if len(ad.BasicAuth) > 0 && !checkBasic(r, ad.BasicAuth) {
		w.Header().Set("WWW-Authenticate", `Basic realm="goddns-admin"`)
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}

	// Layer 3: login session.
	switch r.URL.Path {
	case "/login":
		h.handleLogin(w, r, ad, peerStr)
		return
	case "/logout":
		http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1,
			HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	user, ok := h.session(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	switch r.URL.Path {
	case "/":
		h.handleDashboard(w, r, user)
	case "/ddns/add":
		h.handleAdd(w, r, user, peerStr)
	case "/ddns/del":
		h.handleDel(w, r, user, peerStr)
	case "/logs":
		h.handleLogs(w, r, user)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) session(r *http.Request) (string, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return "", false
	}
	return parseSession(h.secret, c.Value)
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request, ad *config.AdminConfig, peer string) {
	if r.Method == http.MethodGet {
		if _, ok := h.session(r); ok {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		render(w, loginTmpl, map[string]any{"Version": h.version})
		return
	}
	// POST
	user := strings.TrimSpace(r.FormValue("user"))
	pass := r.FormValue("pass")
	if !verifyCred(ad.Users, user, pass) {
		h.audit(user, peer, "login-failed")
		w.WriteHeader(http.StatusUnauthorized)
		render(w, loginTmpl, map[string]any{"Version": h.version, "Error": "invalid credentials"})
		return
	}
	ttl := time.Duration(ad.SessionTTL) * time.Hour
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: newSession(h.secret, user, ttl), Path: "/",
		MaxAge: int(ttl.Seconds()), HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	h.audit(user, peer, "login-ok")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

type recordView struct {
	FQDN, Zone, LastIP, LastSeen, State string
	TTL                                 uint32
}

type proxyView struct {
	Host, Upstream, Allow string
	Auth                  bool
	Rate                  int
}

func (h *Handler) handleDashboard(w http.ResponseWriter, r *http.Request, user string) {
	cfg := h.cfg()
	recs, err := h.store.List()
	if err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		log.Printf("admin: list: %v", err)
		return
	}
	var rv []recordView
	for _, rec := range recs {
		seen := "never"
		if !rec.LastUpdate.IsZero() && rec.LastUpdate.Unix() > 0 {
			seen = rec.LastUpdate.Format("2006-01-02 15:04")
		}
		state := "enabled"
		if rec.Disabled {
			state = "disabled"
		}
		rv = append(rv, recordView{
			FQDN: rec.FQDN, Zone: rec.Zone, TTL: rec.TTL,
			LastIP: rec.LastIP, LastSeen: seen, State: state,
		})
	}

	var pv []proxyView
	for _, host := range cfg.ProxyHosts() {
		rule := cfg.Proxy[host]
		pv = append(pv, proxyView{
			Host: host, Upstream: rule.Upstream, Allow: strings.Join(rule.Allow, ", "),
			Auth: len(rule.BasicAuth) > 0, Rate: rule.RateLimit,
		})
	}

	render(w, dashTmpl, map[string]any{
		"Version":   h.version,
		"User":      user,
		"CSRF":      csrfToken(h.secret, user),
		"Records":   rv,
		"Proxies":   pv,
		"ProxyOn":   cfg.ProxyEnabled,
		"HasAccess": cfg.AccessLog != "",
		"HasEvent":  cfg.LogFile != "",
	})
}

func (h *Handler) handleAdd(w http.ResponseWriter, r *http.Request, user, peer string) {
	if r.Method != http.MethodPost || !csrfValid(h.secret, user, r.FormValue("csrf")) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	fqdn := strings.TrimSpace(r.FormValue("fqdn"))
	zone := strings.TrimSpace(r.FormValue("zone"))
	ttl, _ := strconv.Atoi(r.FormValue("ttl"))
	if ttl <= 0 {
		ttl = 60
	}
	if fqdn == "" || zone == "" {
		http.Error(w, "fqdn and zone are required", http.StatusBadRequest)
		return
	}
	rec, tok, err := h.store.Add(fqdn, zone, uint32(ttl))
	if err != nil {
		render(w, resultTmpl, map[string]any{"Version": h.version, "Error": err.Error()})
		return
	}
	h.audit(user, peer, "ddns-add fqdn=%s zone=%s ttl=%d", rec.FQDN, rec.Zone, rec.TTL)
	render(w, resultTmpl, map[string]any{
		"Version": h.version, "FQDN": rec.FQDN, "Zone": rec.Zone, "TTL": rec.TTL, "Token": tok,
	})
}

func (h *Handler) handleDel(w http.ResponseWriter, r *http.Request, user, peer string) {
	if r.Method != http.MethodPost || !csrfValid(h.secret, user, r.FormValue("csrf")) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	fqdn := strings.TrimSpace(r.FormValue("fqdn"))
	if err := h.store.Del(fqdn); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.audit(user, peer, "ddns-del fqdn=%s", store.FQDN(fqdn))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *Handler) handleLogs(w http.ResponseWriter, r *http.Request, user string) {
	cfg := h.cfg()
	which := r.URL.Query().Get("which")
	path := cfg.LogFile
	title := "event log"
	if which == "access" {
		path = cfg.AccessLog
		title = "access log"
	}
	if path == "" {
		http.Error(w, "that log is not configured (journald)", http.StatusNotFound)
		return
	}
	lines := tailFile(path, 300)
	render(w, logsTmpl, map[string]any{
		"Version": h.version, "Title": title, "Which": which, "Lines": lines,
	})
}

// --- helpers ---

func checkBasic(r *http.Request, creds []string) bool {
	u, p, ok := r.BasicAuth()
	if !ok {
		return false
	}
	return verifyCred(creds, u, p)
}

// verifyCred matches user+pass against a "user:bcrypt" list, burning a dummy
// compare on unknown users to flatten timing.
func verifyCred(creds []string, user, pass string) bool {
	for _, c := range creds {
		u, hash, ok := strings.Cut(c, ":")
		if ok && u == user {
			return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass)) == nil
		}
	}
	_ = bcrypt.CompareHashAndPassword(
		[]byte("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"), []byte(pass))
	return false
}

// tailFile returns the last n lines of path (best-effort, bounded read).
func tailFile(path string, n int) []string {
	f, err := os.Open(path)
	if err != nil {
		return []string{"(cannot read " + path + ": " + err.Error() + ")"}
	}
	defer f.Close()
	// Read the tail of the file only, so a huge log doesn't blow memory.
	const window = 256 * 1024
	if st, err := f.Stat(); err == nil && st.Size() > window {
		_, _ = f.Seek(-window, os.SEEK_END)
	}
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	// newest first
	sort.SliceStable(lines, func(i, j int) bool { return i > j })
	return lines
}
