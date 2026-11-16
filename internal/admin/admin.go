// Package admin is the optional built-in web UI: a read-only dashboard
// (DDNS records, proxy table, log tail) plus DDNS token CRUD. It is served
// as a vhost on the proxy listener and gated by, in order: a CIDR allowlist,
// an optional outer HTTP Basic gate, and a login session (signed cookie).
// It can rewrite DNS, so the layers are deliberate — see README.
package admin

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/named"
	"github.com/chrismfz/goddns/internal/proxy"
	"github.com/chrismfz/goddns/internal/service"
	"github.com/chrismfz/goddns/internal/store"
)

const cookieName = "goddns_admin"

// Store is the slice of the token store the admin UI needs.
type Store = service.Store

// Handler serves the admin UI. Construct with New. It owns only the HTTP
// concerns (gates, sessions, CSRF, forms, templates); every operation goes
// through the service layer, which the machine API and the CLI share.
type Handler struct {
	cfg      func() *config.Config // live config (admin auth + proxy table)
	svc      *service.Service
	secret   []byte
	version  string
	throttle *loginThrottle

	// proxyStats returns the live per-host traffic snapshot; nil ⇒ the proxy is
	// off (or stats not wired) and the dashboard hides the traffic panel.
	proxyStats func() []proxy.HostStat
}

func New(cfg func() *config.Config, st Store, secret []byte, version string) *Handler {
	return &Handler{cfg: cfg, svc: service.New(cfg, st), secret: secret, version: version, throttle: newLoginThrottle()}
}

// SetProxyStats wires the live per-host proxy traffic counters into the
// dashboard's "Proxy traffic" panel.
func (h *Handler) SetProxyStats(fn func() []proxy.HostStat) { h.proxyStats = fn }

// EnableVhostEditing turns on proxy-vhost CRUD in the UI: confPath locates
// proxy.d/, and reload (optional) is called after a successful write so the
// change applies immediately instead of waiting for the poll.
func (h *Handler) EnableVhostEditing(confPath string, reload func()) {
	h.svc.ConfPath = confPath
	h.svc.Reload = reload
}

// credFP is the credential fingerprint sessions and CSRF tokens are bound to
// (the service changes it on a password or role change).
func (h *Handler) credFP(user string) string {
	_, fp, _ := h.svc.Lookup(user)
	return fp
}

func (h *Handler) csrfFor(user string) string {
	return csrfToken(h.secret, h.credFP(user), user)
}

func (h *Handler) csrfOK(user, got string) bool {
	_, fp, ok := h.svc.Lookup(user)
	return ok && csrfValid(h.secret, fp, user, got)
}

func clientIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(host)
}

// audit logs a session event (login) through the service's audit funnel, so
// the admin-audit format is defined in one place.
func (h *Handler) audit(user, peer, format string, args ...any) {
	h.svc.Audit(service.Actor{User: user, Peer: peer}, format, args...)
}

// renderOpErr renders a service error: a missing required field is a plain
// 400 (what the handlers always answered), a role refusal a plain 403,
// anything else the result page.
func (h *Handler) renderOpErr(w http.ResponseWriter, err error) {
	switch {
	case service.IsForbidden(err):
		http.Error(w, "forbidden", http.StatusForbidden)
	case service.IsMissing(err):
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		renderRecordErr(w, h.version, "%v", err)
	}
}

// userPaths are the only pages a non-admin login reaches. Everything else is
// refused here AND by the service's role check (two layers: some admin pages
// — logs, the hash helper, proxy stats — read files without the service).
var userPaths = map[string]bool{
	"/": true, "/account": true,
	// zone pages: the service scopes every one of these to the user's grants
	"/zones": true, "/zone": true, "/zone/record": true, "/zone/restore": true,
	"/ddns/add": true, "/ddns/del": true, "/ddns/rotate": true, "/ddns/help": true,
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
		h.handleLogin(w, r, peerStr)
		return
	case "/logout":
		http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1,
			HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	p, ok := h.session(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	a := service.Actor{User: p.Name, Peer: peerStr, Role: p.Role}

	// Layer 4: role. A non-admin reaches only its home, account and the zone
	// pages (which the service scopes to its grants); nothing server-wide.
	if p.Role != service.RoleAdmin {
		if !userPaths[r.URL.Path] {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if r.URL.Path == "/" {
			h.handleUserHome(w, r, a)
			return
		}
	}

	switch r.URL.Path {
	case "/":
		h.handleDashboard(w, r, a)
	case "/ddns/add":
		h.handleAdd(w, r, a)
	case "/ddns/del":
		h.handleDel(w, r, a)
	case "/ddns/rotate":
		h.handleRotate(w, r, a)
	case "/ddns/help":
		h.handleHelp(w, r, a)
	case "/logs":
		h.handleLogs(w, r, a)
	case "/traffic":
		h.handleTraffic(w, r, a)
	case "/zones":
		h.handleZones(w, r, a)
	case "/zone":
		h.handleZone(w, r, a)
	case "/zone/record":
		h.handleRecord(w, r, a)
	case "/zone/restore":
		h.handleRestore(w, r, a)
	case "/passwd":
		h.handlePasswd(w, r, a)
	case "/proxy/edit":
		h.handleProxyEdit(w, r, a)
	case "/proxy/set":
		h.handleProxySet(w, r, a)
	case "/proxy/del":
		h.handleProxyDel(w, r, a)
	case "/users":
		h.handleUsers(w, r, a)
	case "/account":
		h.handleAccount(w, r, a)
	default:
		http.NotFound(w, r)
	}
}

type zoneRow struct {
	View, Name, Kind, File, Status, Keys string
	NS, NSClass                          string // on-demand live NS-serial verdict
	Dynamic                              bool
}
type keyRow struct{ Name, Algorithm string }
type findRow struct{ Mark, Class, Zone, Message string }
type rrRow struct {
	Name, Type, Data, Full string // Full = zone-file line, for the delete form
	TTL                    uint32
}
type nsRow struct {
	Name, Addr, Note string
	Serial           uint32
	OK               bool
}
type snapRow struct {
	Serial uint32
	Taken  string
	ID     int64
}

// handleZoneHistory is the read-only per-zone history view: the stored snapshot
// list plus the diff of the most recent change (what records moved, with the
// SOA serial noise filtered out). Snapshots are captured by the serve poller.
func (h *Handler) handleZoneHistory(w http.ResponseWriter, a service.Actor, name string) {
	user := a.User
	hist, err := h.svc.History(a, name)
	if service.IsForbidden(err) {
		h.renderOpErr(w, err)
		return
	}
	if err != nil {
		render(w, zoneHistTmpl, map[string]any{"Version": h.version, "User": user, "Name": name, "Error": err.Error(), "Restricted": a.Role != service.RoleAdmin})
		return
	}
	data := map[string]any{"Version": h.version, "User": user, "Active": "zones", "Name": name, "Restricted": a.Role != service.RoleAdmin}
	rows := make([]snapRow, 0, len(hist.Snapshots))
	for _, s := range hist.Snapshots {
		rows = append(rows, snapRow{Serial: s.Serial, Taken: s.TakenAt.Format("2006-01-02 15:04"), ID: s.ID})
	}
	data["Snaps"] = rows

	// Show restore controls only where goddns can actually write (dynamic zone,
	// held key). The restore POST is CSRF-checked like every mutating action.
	if hist.Restorable {
		data["Editable"] = true
		data["CSRF"] = h.csrfFor(user)
	}
	if hist.HasDiff {
		data["Added"] = hist.Added
		data["Removed"] = hist.Removed
		data["FromSerial"] = hist.FromSerial
		data["ToSerial"] = hist.ToSerial
		data["HasDiff"] = true
	}
	render(w, zoneHistTmpl, data)
}

var sevMark = map[named.Severity]string{named.OK: "✓", named.Info: "·", named.Warn: "⚠", named.Error: "✗"}

// handleZone is the read-only per-zone viewer: it pulls the LIVE records from
// BIND via AXFR (journal-merged) so the operator sees exactly what the server
// answers, including anything written dynamically. Read-only: AXFR is a query.
func (h *Handler) handleZone(w http.ResponseWriter, r *http.Request, a service.Actor) {
	user := a.User
	name := service.NormalizeZone(r.URL.Query().Get("name"))
	if name == "" {
		http.Redirect(w, r, "/zones", http.StatusSeeOther)
		return
	}
	if r.URL.Query().Get("history") == "1" {
		h.handleZoneHistory(w, a, name)
		return
	}

	// Tier 2 (the live per-nameserver SOA probe) only on demand — N DNS queries.
	v, err := h.svc.Zone(a, name, r.URL.Query().Get("check") == "1")
	if service.IsForbidden(err) {
		h.renderOpErr(w, err)
		return
	}
	if err != nil {
		render(w, zoneViewTmpl, map[string]any{
			"Version": h.version, "User": user, "Name": name, "Error": err.Error(), "Restricted": a.Role != service.RoleAdmin,
		})
		return
	}

	var rows []rrRow
	for _, row := range named.Rows(v.Records) {
		rows = append(rows, rrRow{
			Name: row.Name, TTL: row.TTL, Type: row.Type, Data: row.Data,
			Full: fmt.Sprintf("%s %d IN %s %s", row.Name, row.TTL, row.Type, row.Data),
		})
	}
	data := map[string]any{
		"Version": h.version, "User": user, "Active": "zones", "Name": name, "Restricted": a.Role != service.RoleAdmin,
		"InConf": v.Conf != nil, "Records": rows, "Count": len(v.Records),
	}
	if z := v.Conf; z != nil {
		data["Kind"] = z.Kind()
		data["Dynamic"] = z.Dynamic
		if a.Role == service.RoleAdmin {
			data["Keys"] = strings.Join(z.UpdateKeys, ", ")
		}
	}
	if a.Role == service.RoleAdmin { // names the TSIG key used for the transfer
		data["Auth"] = v.Auth
	}
	if z := v.Conf; z != nil {
		if v.Editable {
			data["Editable"] = true
			data["CSRF"] = h.csrfFor(user)
			data["FileEdit"] = v.FileEdit // static, edited in place
		}
	}
	if soa := named.SOAOf(v.Records); soa != nil {
		data["Serial"] = soa.Serial
		data["Primary"] = strings.TrimSuffix(soa.Ns, ".")
	}
	if signed, n := named.Signed(v.Records); signed {
		data["Signed"] = true
		data["SignedCount"] = n
	}

	// Tier 1: offline SOA-vs-NS checks (always, no network).
	var dr []findRow
	for _, f := range v.Delegation {
		dr = append(dr, findRow{Mark: sevMark[f.Severity], Class: f.Severity.String(), Message: f.Message})
	}
	data["Delegation"] = dr

	if v.Checked {
		var nsr []nsRow
		for _, c := range v.NS {
			addr := ""
			if len(c.Addrs) > 0 {
				addr = c.Addrs[0]
			}
			nsr = append(nsr, nsRow{Name: c.Name, Addr: addr, Serial: c.Serial, OK: c.OK, Note: c.Note})
		}
		data["Checked"] = true
		data["NS"] = nsr
		data["Agree"] = v.Agree
		data["NoAuth"] = v.NoAuth
	}
	render(w, zoneViewTmpl, data)
}

// handleRecord adds or deletes a record. Like the destructive token actions it
// is two-phase: the first POST renders a diff/confirm page, and only confirm=1
// applies (CSRF-checked; the service routes by zone ownership, snapshots or
// backs up first, and audits).
func (h *Handler) handleRecord(w http.ResponseWriter, r *http.Request, a service.Actor) {
	user := a.User
	if r.Method != http.MethodPost || !h.csrfOK(user, r.FormValue("csrf")) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	zone := strings.TrimSpace(r.FormValue("zone"))
	action := r.FormValue("action")
	line := strings.TrimSpace(r.FormValue("rr"))
	apply := r.FormValue("confirm") == "1"
	res, err := h.svc.EditRecord(a, zone, action, line, apply)
	if err != nil {
		h.renderOpErr(w, err)
		return
	}
	if !apply {
		render(w, recordConfirmTmpl, map[string]any{
			"Version": h.version, "CSRF": h.csrfFor(user), "Zone": zone,
			"Action": action, "RR": line, "Added": res.Added, "Removed": res.Removed,
		})
		return
	}
	http.Redirect(w, r, "/zone?name="+url.QueryEscape(zone), http.StatusSeeOther)
}

// handleRestore rolls a dynamic zone back to a Phase-1 snapshot. Two-phase like
// handleRecord: the first POST previews the forward delta (what records the
// restore would add/remove) and only confirm=1 applies it — CSRF-checked,
// audited, and itself snapshotted-before (so a restore is undoable).
func (h *Handler) handleRestore(w http.ResponseWriter, r *http.Request, a service.Actor) {
	user := a.User
	if r.Method != http.MethodPost || !h.csrfOK(user, r.FormValue("csrf")) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	zone := strings.TrimSpace(r.FormValue("zone"))
	var id int64
	if _, err := fmt.Sscan(strings.TrimSpace(r.FormValue("id")), &id); err != nil {
		http.Error(w, "missing fields", http.StatusBadRequest)
		return
	}
	apply := r.FormValue("confirm") == "1"
	res, err := h.svc.Restore(a, zone, id, apply)
	if err != nil {
		h.renderOpErr(w, err)
		return
	}
	if !apply {
		render(w, restoreConfirmTmpl, map[string]any{
			"Version": h.version, "CSRF": h.csrfFor(user), "Zone": zone,
			"ID": id, "Serial": res.Snapshot.Serial, "Taken": res.Snapshot.TakenAt.Format("2006-01-02 15:04"),
			"Added": res.Added, "Removed": res.Removed,
		})
		return
	}
	http.Redirect(w, r, "/zone?name="+url.QueryEscape(zone)+"&history=1", http.StatusSeeOther)
}

func renderRecordErr(w http.ResponseWriter, version, format string, a ...any) {
	render(w, resultTmpl, map[string]any{"Version": version, "Error": fmt.Sprintf(format, a...)})
}

// handleZones is the read-only BIND introspection page (zones, dynamic flags,
// TSIG health). It shells out to `named-checkconf -p`; if goddns can't read
// named.conf (it runs as the goddns user) the page explains how to allow it.
func (h *Handler) handleZones(w http.ResponseWriter, r *http.Request, a service.Actor) {
	user := a.User
	check := r.URL.Query().Get("check") == "1"
	zl, err := h.svc.Zones(a)
	if err != nil {
		render(w, zonesTmpl, map[string]any{"Version": h.version, "User": user, "Error": err.Error(), "Restricted": a.Role != service.RoleAdmin})
		return
	}

	zr := make([]zoneRow, len(zl.Zones))
	hasViews := false
	for i, z := range zl.Zones {
		if z.View != "" {
			hasViews = true
		}
		zr[i] = zoneRow{View: z.View, Name: z.Name, Kind: z.Kind(), Dynamic: z.Dynamic}
		if a.Role == service.RoleAdmin { // file paths and key names are server detail
			zr[i].File, zr[i].Status = z.Path, named.FileStatus(z.Path, z.Dynamic)
			zr[i].Keys = strings.Join(z.UpdateKeys, ", ")
		}
	}
	// On demand: probe every zone's nameservers for serial agreement. Off by
	// default to keep the list snappy.
	if check {
		vs, err := h.svc.NSVerdicts(a, zl.Zones)
		if err != nil {
			h.renderOpErr(w, err)
			return
		}
		for i, v := range vs {
			zr[i].NS, zr[i].NSClass = nsVerdictView(v)
		}
	}
	var kr []keyRow
	for _, k := range zl.Keys {
		kr = append(kr, keyRow{Name: k.Name, Algorithm: k.Algorithm}) // secret never exposed
	}
	var fr []findRow
	for _, f := range zl.Findings {
		fr = append(fr, findRow{Mark: sevMark[f.Severity], Class: f.Severity.String(), Zone: f.Zone, Message: f.Message})
	}

	render(w, zonesTmpl, map[string]any{
		"Version": h.version, "User": user, "Active": "zones", "Directory": zl.Directory, "Restricted": a.Role != service.RoleAdmin,
		"Zones": zr, "Keys": kr, "Findings": fr, "HasViews": hasViews,
		"Builtin": zl.Builtin, "Checked": check,
	})
}

// nsVerdictView renders a live NS-serial verdict as a short status and a CSS
// class (blank for zones with no apex NS set to compare).
func nsVerdictView(v service.NSVerdict) (status, class string) {
	switch v.Status {
	case service.NSAgree:
		return fmt.Sprintf("✓ %d", v.Serial), "ok"
	case service.NSMismatch:
		return "✗ mismatch", "err"
	case service.NSUnreachable:
		return "unreachable", "warn"
	case service.NSNone:
		return "no NS", "muted"
	default:
		return "", ""
	}
}

func (h *Handler) session(r *http.Request) (service.Principal, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return service.Principal{}, false
	}
	var p service.Principal
	user, ok := parseSession(h.secret, c.Value, func(u string) (string, bool) {
		var fp string
		var ok bool
		p, fp, ok = h.svc.Lookup(u)
		return fp, ok
	})
	if !ok {
		return service.Principal{}, false
	}
	p.Name = user
	return p, true
}

// setSession issues a session cookie bound to user's current credential
// fingerprint (after a login, or to keep a user signed in across their own
// password change, which rotates the fingerprint).
func (h *Handler) setSession(w http.ResponseWriter, user string) {
	ttl := time.Duration(h.cfg().Admin.SessionTTL) * time.Hour
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: newSession(h.secret, h.credFP(user), user, ttl), Path: "/",
		MaxAge: int(ttl.Seconds()), HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
}

func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request, peer string) {
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
	// Throttle by client IP only (fail2ban-style): this locks an attacking
	// source without letting anyone lock out a legit account by failing its
	// login. Throttling runs BEFORE the (expensive) password hash so a flood
	// can't pin the CPU, regardless of whether basic_auth is set.
	ipKey := "ip:" + peer
	if until := h.throttle.blockedUntil(ipKey); !until.IsZero() {
		w.Header().Set("Retry-After", strconv.Itoa(int(time.Until(until).Seconds())+1))
		renderStatus(w, http.StatusTooManyRequests, loginTmpl, map[string]any{"Version": h.version, "Error": "too many attempts — wait a minute"})
		h.audit(user, peer, "login-throttled")
		return
	}
	p, ok, err := h.svc.Login(user, pass)
	if err != nil { // the check couldn't run (hash slots full): not a wrong password
		w.Header().Set("Retry-After", "5")
		renderStatus(w, http.StatusServiceUnavailable, loginTmpl, map[string]any{"Version": h.version, "Error": "busy — try again in a few seconds"})
		h.audit(user, peer, "login-busy")
		return
	}
	if !ok {
		h.throttle.fail(ipKey)
		h.audit(user, peer, "login-failed")
		renderStatus(w, http.StatusUnauthorized, loginTmpl, map[string]any{"Version": h.version, "Error": "invalid credentials"})
		return
	}
	h.throttle.ok(ipKey)
	h.setSession(w, p.Name)
	h.audit(p.Name, peer, "login-ok role=%s", p.Role)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func stampTime(t time.Time) string {
	if t.IsZero() || t.Unix() <= 0 {
		return "never"
	}
	return t.Format("2006-01-02 15:04")
}

// recordViews renders DDNS records for the ddnstable template.
func recordViews(recs []store.Record) []recordView {
	var rv []recordView
	for _, rec := range recs {
		state := "enabled"
		if rec.Disabled {
			state = "disabled"
		}
		rv = append(rv, recordView{
			FQDN: rec.FQDN, Zone: rec.Zone, TTL: rec.TTL, LastIP: rec.LastIP,
			LastChange: stampTime(rec.LastUpdate), LastSeen: stampTime(rec.LastSeen), State: state,
		})
	}
	return rv
}

type recordView struct {
	FQDN, Zone, LastIP, LastChange, LastSeen, State string
	TTL                                             uint32
}

type proxyView struct {
	Host, Upstream, Allow string
	Auth                  bool
	Rate                  int
	Managed               bool // goddns owns the proxy.d/ fragment (editable)
}

type proxyStatView struct {
	Host             string
	Active, Requests int64
	In, Out          string // human-readable byte totals
	Codes            string // "2xx / 3xx / 4xx / 5xx"
	LastSeen         string
}

// joinInts renders a port list as comma-separated text for the vhost form.
func joinInts(ns []int) string {
	parts := make([]string, len(ns))
	for i, n := range ns {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ", ")
}

// humanBytes renders a byte count as B/KB/MB/GB/TB/PB/EB (1024-based, one
// decimal). int64 maxes out in the exabyte range, so the units string covers
// every representable value; exp is clamped as belt-and-braces so an oversized
// total can never index past it (a panic in the dashboard handler).
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	const units = "KMGTPE"
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit && exp < len(units)-1; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), units[exp])
}

func (h *Handler) handleDashboard(w http.ResponseWriter, r *http.Request, a service.Actor) {
	user := a.User
	cfg := h.cfg()
	recs, err := h.svc.DDNSList(a)
	if err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		log.Printf("admin: list: %v", err)
		return
	}
	stamp := stampTime
	rv := recordViews(recs)

	// Which vhosts goddns owns (proxy.d/ fragments) — those get edit/del
	// controls; base-config vhosts stay read-only. Best-effort: on any error
	// nothing is marked managed and the table is read-only.
	managed := h.svc.VhostManaged(a)
	var pv []proxyView
	for _, host := range cfg.ProxyHosts() {
		rule := cfg.Proxy[host]
		pv = append(pv, proxyView{
			Host: host, Upstream: rule.Upstream, Allow: strings.Join(rule.Allow, ", "),
			Auth: len(rule.BasicAuth) > 0, Rate: rule.RateLimit,
			Managed: managed[strings.TrimSuffix(strings.ToLower(host), ".")],
		})
	}

	var ps []proxyStatView
	if h.proxyStats != nil {
		for _, s := range h.proxyStats() {
			ps = append(ps, proxyStatView{
				Host: s.Host, Active: s.Active, Requests: s.Requests,
				In: humanBytes(s.BytesIn), Out: humanBytes(s.BytesOut),
				Codes:    fmt.Sprintf("%d / %d / %d / %d", s.Status2xx, s.Status3xx, s.Status4xx, s.Status5xx),
				LastSeen: stamp(s.LastSeen),
			})
		}
	}

	render(w, dashTmpl, map[string]any{
		"Version":    h.version,
		"User":       user,
		"Active":     "dash",
		"CSRF":       h.csrfFor(user),
		"Records":    rv,
		"Proxies":    pv,
		"ProxyOn":    cfg.ProxyEnabled,
		"ProxyEdit":  h.svc.VhostEditing(),
		"ProxyStats": ps,
		"HasStats":   len(ps) > 0,
		"HasAccess":  cfg.AccessLog != "",
		"HasEvent":   cfg.LogFile != "",
	})
}

type trafficView struct {
	Host, Period string
	Requests     int64
	In, Out      string
}

// handleTraffic renders the persisted proxy-traffic history: per-month totals
// (last 12) and per-day rows (last 30), summed from the daily store rows.
func (h *Handler) handleTraffic(w http.ResponseWriter, r *http.Request, a service.Actor) {
	user := a.User
	conv := func(rows []store.TrafficRow) []trafficView {
		out := make([]trafficView, 0, len(rows))
		for _, t := range rows {
			out = append(out, trafficView{
				Host: t.Host, Period: t.Period, Requests: t.Requests,
				In: humanBytes(t.BytesIn), Out: humanBytes(t.BytesOut),
			})
		}
		return out
	}
	monthly, err := h.svc.TrafficMonthly(a, 12)
	if err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		log.Printf("admin: traffic monthly: %v", err)
		return
	}
	daily, err := h.svc.TrafficDaily(a, 30)
	if err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		log.Printf("admin: traffic daily: %v", err)
		return
	}
	render(w, trafficTmpl, map[string]any{
		"Version": h.version, "User": user, "Active": "traffic",
		"Monthly": conv(monthly), "Daily": conv(daily),
	})
}

// handlePasswd is the in-UI equivalent of `goddns passwd`: type a user and a
// password, get a `user:bcrypt` entry to drop into [admin] users or a vhost's
// basic_auth — so you never need shell access to mint one. It's a pure helper:
// nothing is written (goddns never rewrites your goddns.conf) and the password
// is never stored or logged.
func (h *Handler) handlePasswd(w http.ResponseWriter, r *http.Request, a service.Actor) {
	user := a.User
	data := map[string]any{"Version": h.version, "User": user, "Active": "passwd", "CSRF": h.csrfFor(user)}
	if r.Method == http.MethodPost {
		if !h.csrfOK(user, r.FormValue("csrf")) {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		u := strings.TrimSpace(r.FormValue("u"))
		pw := r.FormValue("pw")
		data["U"] = u
		switch {
		case u == "" || pw == "":
			data["Error"] = "user and password are both required"
		case strings.Contains(u, ":"):
			data["Error"] = "user must not contain ':'"
		case len(pw) < 8:
			data["Error"] = "password too short (min 8 characters)"
		default:
			hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
			if err != nil {
				data["Error"] = err.Error()
			} else {
				data["Entry"] = u + ":" + string(hash)
			}
		}
	}
	render(w, passwdTmpl, data)
}

// proxyRuleFromForm builds a ProxyRule + host from the vhost form fields. A
// plaintext auth_user/auth_pass pair is bcrypt-hashed here and appended to
// basic_auth, so the operator never has to run `goddns passwd` by hand.
func proxyRuleFromForm(r *http.Request) (string, config.ProxyRule, error) {
	host := strings.TrimSpace(r.FormValue("host"))
	rate, _ := strconv.Atoi(r.FormValue("rate"))
	splitLines := func(s string) []string {
		var out []string
		for _, f := range strings.FieldsFunc(s, func(c rune) bool { return c == ',' || c == '\n' || c == '\r' }) {
			if f = strings.TrimSpace(f); f != "" {
				out = append(out, f)
			}
		}
		return out
	}
	var ports []int
	for _, f := range strings.FieldsFunc(r.FormValue("console_ports"), func(c rune) bool {
		return c == ',' || c == ' ' || c == '\n' || c == '\r' || c == '\t'
	}) {
		if p, err := strconv.Atoi(f); err == nil {
			ports = append(ports, p)
		} else {
			return host, config.ProxyRule{}, fmt.Errorf("console_ports: %q is not a number", f)
		}
	}
	rule := config.ProxyRule{
		Upstream:       strings.TrimSpace(r.FormValue("upstream")),
		UpstreamVerify: r.FormValue("verify") == "1",
		PreserveHost:   r.FormValue("preserve") == "1",
		BMCCompat:      r.FormValue("bmc") == "1",
		ConsolePorts:   ports,
		Allow:          splitLines(r.FormValue("allow")),
		BasicAuth:      splitLines(r.FormValue("auth")),
		RateLimit:      rate,
	}
	if pw := r.FormValue("auth_pass"); pw != "" {
		u := strings.TrimSpace(r.FormValue("auth_user"))
		switch {
		case u == "":
			return host, rule, fmt.Errorf("a login user is required when you set a password")
		case strings.Contains(u, ":"):
			return host, rule, fmt.Errorf("login user must not contain ':'")
		case len(pw) < 8:
			return host, rule, fmt.Errorf("login password too short (min 8 characters)")
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
		if err != nil {
			return host, rule, fmt.Errorf("hash login password: %w", err)
		}
		rule.BasicAuth = append(rule.BasicAuth, u+":"+string(hash))
	}
	return host, rule, nil
}

// handleProxyEdit serves the vhost form pre-filled for an existing managed
// vhost (GET /proxy/edit?host=). The dashboard's inline form covers "add".
func (h *Handler) handleProxyEdit(w http.ResponseWriter, r *http.Request, a service.Actor) {
	user := a.User
	if !h.svc.VhostEditing() {
		http.NotFound(w, r)
		return
	}
	e, err := h.svc.VhostGet(a, r.URL.Query().Get("host"))
	if err != nil {
		renderRecordErr(w, h.version, "%v", err)
		return
	}
	render(w, proxyFormTmpl, map[string]any{
		"Version": h.version, "CSRF": h.csrfFor(user), "Edit": true,
		"Host": e.Host, "Upstream": e.Rule.Upstream,
		"Allow": strings.Join(e.Rule.Allow, ", "), "Auth": strings.Join(e.Rule.BasicAuth, "\n"),
		"Rate": e.Rule.RateLimit, "Verify": e.Rule.UpstreamVerify, "Preserve": e.Rule.PreserveHost,
		"BMC": e.Rule.BMCCompat, "Console": joinInts(e.Rule.ConsolePorts),
	})
}

// handleProxySet creates/replaces a managed vhost. Two-phase like the record
// editor: the first POST previews the rendered fragment, confirm=1 writes it
// (CSRF-checked; the service audits and triggers an immediate reload).
func (h *Handler) handleProxySet(w http.ResponseWriter, r *http.Request, a service.Actor) {
	user := a.User
	if r.Method != http.MethodPost || !h.csrfOK(user, r.FormValue("csrf")) || !h.svc.VhostEditing() {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	host, rule, err := proxyRuleFromForm(r)
	if err != nil {
		renderRecordErr(w, h.version, "%v", err)
		return
	}
	apply := r.FormValue("confirm") == "1"
	res, err := h.svc.VhostSet(a, host, rule, apply)
	if err != nil {
		renderRecordErr(w, h.version, "%v", err)
		return
	}
	if !apply {
		render(w, proxyConfirmTmpl, map[string]any{
			"Version": h.version, "CSRF": h.csrfFor(user),
			"Action": res.Action, "Host": res.Host, "Fragment": res.Fragment,
			"Upstream": rule.Upstream, "Allow": strings.Join(rule.Allow, ", "),
			"Auth": strings.Join(rule.BasicAuth, "\n"), "Rate": rule.RateLimit,
			"Verify": rule.UpstreamVerify, "Preserve": rule.PreserveHost,
			"BMC": rule.BMCCompat, "Console": joinInts(rule.ConsolePorts),
		})
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// handleProxyDel removes a managed vhost (two-phase confirm; the service
// audits and reloads).
func (h *Handler) handleProxyDel(w http.ResponseWriter, r *http.Request, a service.Actor) {
	user := a.User
	if r.Method != http.MethodPost || !h.csrfOK(user, r.FormValue("csrf")) || !h.svc.VhostEditing() {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	apply := r.FormValue("confirm") == "1"
	res, err := h.svc.VhostRemove(a, r.FormValue("host"), apply)
	if err != nil {
		renderRecordErr(w, h.version, "%v", err)
		return
	}
	if !apply {
		render(w, confirmTmpl, map[string]any{
			"Version": h.version, "CSRF": h.csrfFor(user), "FQDN": res.Host, "Host": res.Host,
			"Action": "/proxy/del", "Verb": "yes, remove",
			"Msg": "Remove this proxy vhost? Its " + relBase(res.File) + " fragment is deleted and the route stops on the next reload.",
		})
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func relBase(f string) string { return "proxy.d/" + filepath.Base(f) }

func (h *Handler) handleAdd(w http.ResponseWriter, r *http.Request, a service.Actor) {
	user := a.User
	if r.Method != http.MethodPost || !h.csrfOK(user, r.FormValue("csrf")) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ttl, _ := strconv.Atoi(r.FormValue("ttl"))
	rec, tok, err := h.svc.DDNSAdd(a, r.FormValue("fqdn"), r.FormValue("zone"), ttl)
	if err != nil {
		h.renderOpErr(w, err)
		return
	}
	h.renderHelp(w, rec, tok, true)
}

// endpoint returns the host:port clients use to reach the DDNS update
// endpoint, for the copy-paste help. PublicHost fills it when set; the port
// comes from the listen address.
func (h *Handler) endpoint() (host, port string) {
	cfg := h.cfg()
	host = cfg.PublicHost
	if host == "" {
		host = "<your-goddns-host>"
	}
	if _, p, err := net.SplitHostPort(cfg.Listen); err == nil && p != "" {
		port = p
	} else {
		port = "8245"
	}
	return host, port
}

// renderHelp shows the client setup snippets for a record. token is the
// real value only right after add/rotate (fresh==true); otherwise it's a
// "<token>" placeholder, because goddns stores only the hash.
func (h *Handler) renderHelp(w http.ResponseWriter, rec store.Record, token string, fresh bool) {
	host, port := h.endpoint()
	render(w, helpTmpl, map[string]any{
		"Version":  h.version,
		"FQDN":     rec.FQDN,
		"Name":     strings.TrimSuffix(rec.FQDN, "."),
		"Zone":     rec.Zone,
		"TTL":      rec.TTL,
		"Host":     host,
		"Port":     port,
		"Token":    token,
		"NewToken": fresh,
	})
}

func (h *Handler) handleHelp(w http.ResponseWriter, r *http.Request, a service.Actor) {
	rec, err := h.svc.DDNSGet(a, r.URL.Query().Get("fqdn"))
	if service.IsForbidden(err) {
		h.renderOpErr(w, err)
		return
	}
	if err != nil {
		http.Error(w, "no such record", http.StatusNotFound)
		return
	}
	h.renderHelp(w, rec, "<token>", false)
}

func (h *Handler) handleRotate(w http.ResponseWriter, r *http.Request, a service.Actor) {
	user := a.User
	if r.Method != http.MethodPost || !h.csrfOK(user, r.FormValue("csrf")) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	fqdn := strings.TrimSpace(r.FormValue("fqdn"))
	if r.FormValue("confirm") != "1" {
		render(w, confirmTmpl, map[string]any{
			"Version": h.version, "CSRF": h.csrfFor(user), "FQDN": store.FQDN(fqdn),
			"Action": "/ddns/rotate", "Verb": "yes, rotate",
			"Msg": "Rotate the token? The current token stops working immediately — update your client with the new one.",
		})
		return
	}
	rec, tok, err := h.svc.DDNSRotate(a, fqdn)
	if service.IsForbidden(err) {
		h.renderOpErr(w, err)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.renderHelp(w, rec, tok, true)
}

func (h *Handler) handleDel(w http.ResponseWriter, r *http.Request, a service.Actor) {
	user := a.User
	if r.Method != http.MethodPost || !h.csrfOK(user, r.FormValue("csrf")) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	fqdn := strings.TrimSpace(r.FormValue("fqdn"))
	// No-JS confirmation: the first POST (CSRF-checked) renders a confirm
	// page; only confirm=1 actually deletes. Replaces an inline onsubmit
	// confirm() that the page CSP (no scripts) would block anyway.
	if r.FormValue("confirm") != "1" {
		render(w, confirmTmpl, map[string]any{
			"Version": h.version, "CSRF": h.csrfFor(user), "FQDN": store.FQDN(fqdn),
			"Action": "/ddns/del", "Verb": "yes, delete",
			"Msg": "Delete this record? Its token stops working immediately (you can re-add it later).",
		})
		return
	}
	if err := h.svc.DDNSDel(a, fqdn); service.IsForbidden(err) {
		h.renderOpErr(w, err)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *Handler) handleLogs(w http.ResponseWriter, r *http.Request, a service.Actor) {
	user := a.User
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
		"Version": h.version, "User": user, "Active": "logs", "Title": title, "Which": which, "Lines": lines,
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

// verifyCred matches user+pass against a "user:bcrypt" list. On an unknown
// user it still runs exactly one bcrypt compare, against a REAL entry's hash
// so the cost (and therefore the timing) matches an existing-user wrong-
// password attempt — closing the username-enumeration channel.
func verifyCred(creds []string, user, pass string) bool {
	dummy := "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
	for i, c := range creds {
		u, hash, ok := strings.Cut(c, ":")
		if !ok {
			continue
		}
		if i == 0 || dummy == "" {
			dummy = hash // first real entry sets the dummy cost
		}
		if u == user {
			return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass)) == nil
		}
	}
	_ = bcrypt.CompareHashAndPassword([]byte(dummy), []byte(pass))
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
