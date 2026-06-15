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
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/crypto/bcrypt"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/ddns"
	"github.com/chrismfz/goddns/internal/history"
	"github.com/chrismfz/goddns/internal/named"
	"github.com/chrismfz/goddns/internal/recordmut"
	"github.com/chrismfz/goddns/internal/store"
	"github.com/chrismfz/goddns/internal/tsig"
	"github.com/chrismfz/goddns/internal/vhostmut"
)

const cookieName = "goddns_admin"

// Store is the slice of the token store the admin UI needs.
type Store interface {
	List() ([]store.Record, error)
	Add(name, zone string, ttl uint32) (store.Record, string, error)
	Del(name string) error
	Rotate(name string) (store.Record, string, error)
	Get(name string) (store.Record, error)
	SnapshotList(zone string, limit int) ([]store.Snapshot, error)
	SnapshotByID(id int64) (store.Snapshot, bool, error)
	SnapshotPut(zone string, serial uint32, content string, keep int) (int64, error)
}

// Handler serves the admin UI. Construct with New.
type Handler struct {
	cfg      func() *config.Config // live config (admin auth + proxy table)
	store    Store
	secret   []byte
	version  string
	throttle *loginThrottle
	confPath string // goddns.conf path, for proxy.d/ vhost editing (empty = read-only)
	reload   func() // optional: trigger an immediate config reload after a write
}

func New(cfg func() *config.Config, st Store, secret []byte, version string) *Handler {
	return &Handler{cfg: cfg, store: st, secret: secret, version: version, throttle: newLoginThrottle()}
}

// EnableVhostEditing turns on proxy-vhost CRUD in the UI: confPath locates
// proxy.d/, and reload (optional) is called after a successful write so the
// change applies immediately instead of waiting for the poll.
func (h *Handler) EnableVhostEditing(confPath string, reload func()) {
	h.confPath = confPath
	h.reload = reload
}

func (h *Handler) vhostEditor() *vhostmut.Editor {
	return &vhostmut.Editor{ConfPath: h.confPath}
}

// adminCred returns the bcrypt hash configured for user (the credential
// fingerprint that sessions/CSRF are bound to), and whether it exists.
func adminCred(ad *config.AdminConfig, user string) (string, bool) {
	for _, c := range ad.Users {
		u, hash, ok := strings.Cut(c, ":")
		if ok && u == user {
			return hash, true
		}
	}
	return "", false
}

func (h *Handler) csrfFor(user string) string {
	fp, _ := adminCred(&h.cfg().Admin, user)
	return csrfToken(h.secret, fp, user)
}

func (h *Handler) csrfOK(user, got string) bool {
	fp, _ := adminCred(&h.cfg().Admin, user)
	return csrfValid(h.secret, fp, user, got)
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
	case "/ddns/rotate":
		h.handleRotate(w, r, user, peerStr)
	case "/ddns/help":
		h.handleHelp(w, r, user)
	case "/logs":
		h.handleLogs(w, r, user)
	case "/zones":
		h.handleZones(w, r, user)
	case "/zone":
		h.handleZone(w, r, user)
	case "/zone/record":
		h.handleRecord(w, r, user, peerStr)
	case "/proxy/edit":
		h.handleProxyEdit(w, r, user)
	case "/proxy/set":
		h.handleProxySet(w, r, user, peerStr)
	case "/proxy/del":
		h.handleProxyDel(w, r, user, peerStr)
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
func (h *Handler) handleZoneHistory(w http.ResponseWriter, user, name string) {
	snaps, err := h.store.SnapshotList(name, 200)
	if err != nil {
		render(w, zoneHistTmpl, map[string]any{"Version": h.version, "User": user, "Name": name, "Error": err.Error()})
		return
	}
	data := map[string]any{"Version": h.version, "User": user, "Name": name}
	rows := make([]snapRow, 0, len(snaps))
	for _, s := range snaps {
		rows = append(rows, snapRow{Serial: s.Serial, Taken: s.TakenAt.Format("2006-01-02 15:04"), ID: s.ID})
	}
	data["Snaps"] = rows

	if len(snaps) >= 2 {
		newer, okN, errN := h.store.SnapshotByID(snaps[0].ID)
		older, okO, errO := h.store.SnapshotByID(snaps[1].ID)
		if errN == nil && errO == nil && okN && okO {
			added, removed := history.Diff(older.Content, newer.Content)
			data["Added"] = history.DropSOA(added)
			data["Removed"] = history.DropSOA(removed)
			data["FromSerial"] = older.Serial
			data["ToSerial"] = newer.Serial
			data["HasDiff"] = true
		}
	}
	render(w, zoneHistTmpl, data)
}

// handleZone is the read-only per-zone viewer: it pulls the LIVE records from
// BIND via AXFR (journal-merged) so the operator sees exactly what the server
// answers, including anything written dynamically. Read-only: AXFR is a query.
func (h *Handler) handleZone(w http.ResponseWriter, r *http.Request, user string) {
	cfg := h.cfg()
	name := strings.TrimSuffix(strings.TrimSpace(r.URL.Query().Get("name")), ".")
	if name == "" {
		http.Redirect(w, r, "/zones", http.StatusSeeOther)
		return
	}
	if r.URL.Query().Get("history") == "1" {
		h.handleZoneHistory(w, user, name)
		return
	}
	nc := cfg.NamedConf
	if nc == "" {
		nc = "/etc/named.conf"
	}
	server := cfg.DNSServer
	if server == "" {
		server = "127.0.0.1:53"
	}

	// named.conf is best-effort: it supplies the dynamic flag and the TSIG
	// keys to authenticate the transfer. Without it we still try unauthenticated.
	inv := &named.Inventory{}
	if data, err := named.CheckConf(nc); err == nil {
		inv = named.Parse(data)
	}
	z := inv.ZoneByName(name)

	records, auth, err := named.TransferAuto(name, server, inv.AXFRKeys(z, cfg.TSIGName))
	if err != nil {
		render(w, zoneViewTmpl, map[string]any{
			"Version": h.version, "User": user, "Name": name, "Error": err.Error(),
		})
		return
	}
	named.SortZone(records)

	var rows []rrRow
	for _, row := range named.Rows(records) {
		rows = append(rows, rrRow{
			Name: row.Name, TTL: row.TTL, Type: row.Type, Data: row.Data,
			Full: fmt.Sprintf("%s %d IN %s %s", row.Name, row.TTL, row.Type, row.Data),
		})
	}
	data := map[string]any{
		"Version": h.version, "User": user, "Name": name,
		"InConf": z != nil, "Records": rows, "Count": len(records), "Auth": auth,
	}
	if z != nil {
		data["Kind"] = z.Kind()
		data["Dynamic"] = z.Dynamic
		data["Keys"] = strings.Join(z.UpdateKeys, ", ")
		if h.editor(cfg).CanEdit(z) {
			data["Editable"] = true
			data["CSRF"] = h.csrfFor(user)
		}
	}
	if soa := named.SOAOf(records); soa != nil {
		data["Serial"] = soa.Serial
		data["Primary"] = strings.TrimSuffix(soa.Ns, ".")
	}
	if signed, n := named.Signed(records); signed {
		data["Signed"] = true
		data["SignedCount"] = n
	}

	// Tier 1: offline SOA-vs-NS checks (always, no network).
	mark := map[named.Severity]string{named.OK: "✓", named.Info: "·", named.Warn: "⚠", named.Error: "✗"}
	var dr []findRow
	for _, f := range named.CheckDelegation(name, records) {
		dr = append(dr, findRow{Mark: mark[f.Severity], Class: f.Severity.String(), Message: f.Message})
	}
	data["Delegation"] = dr

	// Tier 2: live per-nameserver SOA probe (only on demand — N DNS queries).
	if r.URL.Query().Get("check") == "1" {
		checks := named.CheckNameservers(name, records, server)
		var nsr []nsRow
		for _, c := range checks {
			addr := ""
			if len(c.Addrs) > 0 {
				addr = c.Addrs[0]
			}
			nsr = append(nsr, nsRow{Name: c.Name, Addr: addr, Serial: c.Serial, OK: c.OK, Note: c.Note})
		}
		agree, seen := named.SerialsAgree(checks)
		data["Checked"] = true
		data["NS"] = nsr
		data["Agree"] = agree && len(seen) == 1
		data["NoAuth"] = len(seen) == 0
	}
	render(w, zoneViewTmpl, data)
}

// editor builds the record-mutation editor from the live config (keyring or the
// single key), wired to the snapshot store.
func (h *Handler) editor(cfg *config.Config) *recordmut.Editor {
	keys := cfg.TSIGKeys()
	if len(keys) == 0 {
		keys = []tsig.Key{{Name: strings.TrimSuffix(cfg.TSIGName, "."), Algo: cfg.TSIGAlgo, Secret: cfg.TSIGSecret}}
	}
	nc := cfg.NamedConf
	if nc == "" {
		nc = "/etc/named.conf"
	}
	server := cfg.DNSServer
	if server == "" {
		server = "127.0.0.1:53"
	}
	return &recordmut.Editor{NamedConf: nc, DNSServer: server, Keys: keys, Snap: h.store, Keep: cfg.HistoryKeep}
}

// handleRecord adds or deletes a record in a dynamic zone. Like the destructive
// token actions it is two-phase: the first POST renders a diff/confirm page, and
// only confirm=1 applies (CSRF-checked, audited; recordmut snapshots first and
// refuses static/panel zones).
func (h *Handler) handleRecord(w http.ResponseWriter, r *http.Request, user, peer string) {
	if r.Method != http.MethodPost || !h.csrfOK(user, r.FormValue("csrf")) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	zone := strings.TrimSpace(r.FormValue("zone"))
	action := r.FormValue("action")
	line := strings.TrimSpace(r.FormValue("rr"))
	if zone == "" || line == "" || (action != "add" && action != "del") {
		http.Error(w, "missing fields", http.StatusBadRequest)
		return
	}
	rr, err := dns.NewRR(line)
	if err != nil || rr == nil {
		renderRecordErr(w, h.version, "parse record %q: %v", line, err)
		return
	}
	act := ddns.AddRR
	if action == "del" {
		act = ddns.DelRR
	}
	ops := []ddns.Op{{Action: act, RR: rr}}
	ed := h.editor(h.cfg())

	if r.FormValue("confirm") != "1" {
		res, err := ed.Preview(zone, ops)
		if err != nil {
			renderRecordErr(w, h.version, "%v", err)
			return
		}
		render(w, recordConfirmTmpl, map[string]any{
			"Version": h.version, "CSRF": h.csrfFor(user), "Zone": zone,
			"Action": action, "RR": line, "Added": res.Added, "Removed": res.Removed,
		})
		return
	}
	res, err := ed.Apply(zone, ops)
	if err != nil {
		renderRecordErr(w, h.version, "%v", err)
		return
	}
	h.audit(user, peer, "record-%s zone=%s rr=%q key=%s snapshot=%d", action, zone, line, res.Key, res.Snapshot)
	http.Redirect(w, r, "/zone?name="+url.QueryEscape(zone), http.StatusSeeOther)
}

func renderRecordErr(w http.ResponseWriter, version, format string, a ...any) {
	render(w, resultTmpl, map[string]any{"Version": version, "Error": fmt.Sprintf(format, a...)})
}

// handleZones is the read-only BIND introspection page (zones, dynamic flags,
// TSIG health). It shells out to `named-checkconf -p`; if goddns can't read
// named.conf (it runs as the goddns user) the page explains how to allow it.
func (h *Handler) handleZones(w http.ResponseWriter, r *http.Request, user string) {
	cfg := h.cfg()
	nc := cfg.NamedConf
	if nc == "" {
		nc = "/etc/named.conf"
	}
	server := cfg.DNSServer
	if server == "" {
		server = "127.0.0.1:53"
	}
	check := r.URL.Query().Get("check") == "1"

	data, err := named.CheckConf(nc)
	if err != nil {
		render(w, zonesTmpl, map[string]any{"Version": h.version, "User": user, "Error": err.Error()})
		return
	}
	inv := named.Parse(data)

	zones := inv.UserZones()
	zr := make([]zoneRow, len(zones))
	hasViews := false
	for i, z := range zones {
		if z.View != "" {
			hasViews = true
		}
		zr[i] = zoneRow{
			View: z.View, Name: z.Name, Kind: z.Kind(), File: z.Path,
			Status: named.FileStatus(z.Path, z.Dynamic),
			Keys:   strings.Join(z.UpdateKeys, ", "), Dynamic: z.Dynamic,
		}
	}

	// On demand: probe every zone's nameservers for serial agreement. Each
	// zone is a cheap NS query + a few SOA probes (no AXFR), run with a small
	// concurrency cap so a host with many zones can't be made to open a flood
	// of sockets from one click. Off by default to keep the list snappy.
	if check {
		sem := make(chan struct{}, nsCheckConcurrency)
		var wg sync.WaitGroup
		for i := range zones {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				zr[i].NS, zr[i].NSClass = zoneNSVerdict(zones[i], server)
			}(i)
		}
		wg.Wait()
	}
	var kr []keyRow
	for _, k := range inv.Keys {
		kr = append(kr, keyRow{Name: k.Name, Algorithm: k.Algorithm}) // secret never exposed
	}
	var fr []findRow
	for _, f := range inv.Check(cfg.TSIGName, cfg.TSIGSecret) {
		mark := map[named.Severity]string{named.OK: "✓", named.Info: "·", named.Warn: "⚠", named.Error: "✗"}[f.Severity]
		fr = append(fr, findRow{Mark: mark, Class: f.Severity.String(), Zone: f.Zone, Message: f.Message})
	}

	render(w, zonesTmpl, map[string]any{
		"Version": h.version, "User": user, "Directory": inv.Directory,
		"Zones": zr, "Keys": kr, "Findings": fr, "HasViews": hasViews,
		"Builtin": len(inv.Zones) - len(zr), "Checked": check,
	})
}

// nsCheckConcurrency bounds how many zones are probed at once on /zones?check=1.
const nsCheckConcurrency = 8

// zoneNSVerdict runs the on-demand live NS-serial check for one zone (a cheap
// apex NS query, then a direct SOA probe to each nameserver). Returns a short
// status and a CSS class. Non-master zones (hint/slave/forward) return blank —
// there's no apex NS set to compare. Read-only.
func zoneNSVerdict(z named.Zone, server string) (status, class string) {
	switch z.Kind() {
	case "static file", "dynamic":
	default:
		return "", ""
	}
	switch st, serial := named.ZoneSerialCheck(z.Name, server); st {
	case named.SerialAgree:
		return fmt.Sprintf("✓ %d", serial), "ok"
	case named.SerialMismatch:
		return "✗ mismatch", "err"
	case named.SerialUnreachable:
		return "unreachable", "warn"
	default:
		return "no NS", "muted"
	}
}

func (h *Handler) session(r *http.Request) (string, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return "", false
	}
	ad := &h.cfg().Admin
	return parseSession(h.secret, c.Value, func(u string) (string, bool) { return adminCred(ad, u) })
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
	// Throttle by client IP only (fail2ban-style): this locks an attacking
	// source without letting anyone lock out a legit account by failing its
	// login. Throttling runs BEFORE the (expensive) bcrypt compare so a
	// flood can't pin the CPU, regardless of whether basic_auth is set.
	ipKey := "ip:" + peer
	if until := h.throttle.blockedUntil(ipKey); !until.IsZero() {
		w.Header().Set("Retry-After", strconv.Itoa(int(time.Until(until).Seconds())+1))
		w.WriteHeader(http.StatusTooManyRequests)
		render(w, loginTmpl, map[string]any{"Version": h.version, "Error": "too many attempts — wait a minute"})
		h.audit(user, peer, "login-throttled")
		return
	}
	if !verifyCred(ad.Users, user, pass) {
		h.throttle.fail(ipKey)
		h.audit(user, peer, "login-failed")
		w.WriteHeader(http.StatusUnauthorized)
		render(w, loginTmpl, map[string]any{"Version": h.version, "Error": "invalid credentials"})
		return
	}
	h.throttle.ok(ipKey)
	fp, _ := adminCred(ad, user)
	ttl := time.Duration(ad.SessionTTL) * time.Hour
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: newSession(h.secret, fp, user, ttl), Path: "/",
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
	Managed               bool // goddns owns the proxy.d/ fragment (editable)
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

	// Which vhosts goddns owns (proxy.d/ fragments) — those get edit/del
	// controls; base-config vhosts stay read-only. Best-effort: on any error
	// nothing is marked managed and the table is read-only.
	managed := map[string]bool{}
	if h.confPath != "" {
		if entries, err := h.vhostEditor().List(); err == nil {
			for _, e := range entries {
				managed[e.Host] = e.Managed
			}
		}
	}
	var pv []proxyView
	for _, host := range cfg.ProxyHosts() {
		rule := cfg.Proxy[host]
		pv = append(pv, proxyView{
			Host: host, Upstream: rule.Upstream, Allow: strings.Join(rule.Allow, ", "),
			Auth: len(rule.BasicAuth) > 0, Rate: rule.RateLimit,
			Managed: managed[strings.TrimSuffix(strings.ToLower(host), ".")],
		})
	}

	render(w, dashTmpl, map[string]any{
		"Version":   h.version,
		"User":      user,
		"CSRF":      h.csrfFor(user),
		"Records":   rv,
		"Proxies":   pv,
		"ProxyOn":   cfg.ProxyEnabled,
		"ProxyEdit": h.confPath != "",
		"HasAccess": cfg.AccessLog != "",
		"HasEvent":  cfg.LogFile != "",
	})
}

// proxyRuleFromForm builds a ProxyRule + host from the vhost form fields.
func proxyRuleFromForm(r *http.Request) (string, config.ProxyRule) {
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
	return host, config.ProxyRule{
		Upstream:       strings.TrimSpace(r.FormValue("upstream")),
		UpstreamVerify: r.FormValue("verify") == "1",
		PreserveHost:   r.FormValue("preserve") == "1",
		Allow:          splitLines(r.FormValue("allow")),
		BasicAuth:      splitLines(r.FormValue("auth")),
		RateLimit:      rate,
	}
}

// handleProxyEdit serves the vhost form pre-filled for an existing managed
// vhost (GET /proxy/edit?host=). The dashboard's inline form covers "add".
func (h *Handler) handleProxyEdit(w http.ResponseWriter, r *http.Request, user string) {
	if h.confPath == "" {
		http.NotFound(w, r)
		return
	}
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(r.URL.Query().Get("host"))), ".")
	entries, err := h.vhostEditor().List()
	if err != nil {
		renderRecordErr(w, h.version, "%v", err)
		return
	}
	for _, e := range entries {
		if e.Host == host && e.Managed {
			render(w, proxyFormTmpl, map[string]any{
				"Version": h.version, "CSRF": h.csrfFor(user), "Edit": true,
				"Host": e.Host, "Upstream": e.Rule.Upstream,
				"Allow": strings.Join(e.Rule.Allow, ", "), "Auth": strings.Join(e.Rule.BasicAuth, "\n"),
				"Rate": e.Rule.RateLimit, "Verify": e.Rule.UpstreamVerify, "Preserve": e.Rule.PreserveHost,
			})
			return
		}
	}
	renderRecordErr(w, h.version, "no goddns-managed vhost %q to edit", host)
}

// handleProxySet creates/replaces a managed vhost. Two-phase like the record
// editor: the first POST previews the rendered fragment, confirm=1 writes it
// (CSRF-checked, audited) and triggers an immediate reload.
func (h *Handler) handleProxySet(w http.ResponseWriter, r *http.Request, user, peer string) {
	if r.Method != http.MethodPost || !h.csrfOK(user, r.FormValue("csrf")) || h.confPath == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	host, rule := proxyRuleFromForm(r)
	ed := h.vhostEditor()
	res, err := ed.PreviewSet(host, rule)
	if err != nil {
		renderRecordErr(w, h.version, "%v", err)
		return
	}
	if r.FormValue("confirm") != "1" {
		render(w, proxyConfirmTmpl, map[string]any{
			"Version": h.version, "CSRF": h.csrfFor(user),
			"Action": res.Action, "Host": res.Host, "Fragment": res.Fragment,
			"Upstream": rule.Upstream, "Allow": strings.Join(rule.Allow, ", "),
			"Auth": strings.Join(rule.BasicAuth, "\n"), "Rate": rule.RateLimit,
			"Verify": rule.UpstreamVerify, "Preserve": rule.PreserveHost,
		})
		return
	}
	if _, err := ed.Set(host, rule); err != nil {
		renderRecordErr(w, h.version, "%v", err)
		return
	}
	h.audit(user, peer, "vhost-%s host=%s upstream=%s", res.Action, res.Host, rule.Upstream)
	if h.reload != nil {
		h.reload()
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// handleProxyDel removes a managed vhost (two-phase confirm, audited, reloads).
func (h *Handler) handleProxyDel(w http.ResponseWriter, r *http.Request, user, peer string) {
	if r.Method != http.MethodPost || !h.csrfOK(user, r.FormValue("csrf")) || h.confPath == "" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	host := strings.TrimSpace(r.FormValue("host"))
	ed := h.vhostEditor()
	res, err := ed.PreviewRemove(host)
	if err != nil {
		renderRecordErr(w, h.version, "%v", err)
		return
	}
	if r.FormValue("confirm") != "1" {
		render(w, confirmTmpl, map[string]any{
			"Version": h.version, "CSRF": h.csrfFor(user), "FQDN": res.Host, "Host": res.Host,
			"Action": "/proxy/del", "Verb": "yes, remove",
			"Msg": "Remove this proxy vhost? Its " + relBase(res.File) + " fragment is deleted and the route stops on the next reload.",
		})
		return
	}
	if _, err := ed.Remove(host); err != nil {
		renderRecordErr(w, h.version, "%v", err)
		return
	}
	h.audit(user, peer, "vhost-remove host=%s", res.Host)
	if h.reload != nil {
		h.reload()
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func relBase(f string) string { return "proxy.d/" + filepath.Base(f) }

func (h *Handler) handleAdd(w http.ResponseWriter, r *http.Request, user, peer string) {
	if r.Method != http.MethodPost || !h.csrfOK(user, r.FormValue("csrf")) {
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

func (h *Handler) handleHelp(w http.ResponseWriter, r *http.Request, user string) {
	rec, err := h.store.Get(strings.TrimSpace(r.URL.Query().Get("fqdn")))
	if err != nil {
		http.Error(w, "no such record", http.StatusNotFound)
		return
	}
	h.renderHelp(w, rec, "<token>", false)
}

func (h *Handler) handleRotate(w http.ResponseWriter, r *http.Request, user, peer string) {
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
	rec, tok, err := h.store.Rotate(fqdn)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.audit(user, peer, "ddns-rotate fqdn=%s", rec.FQDN)
	h.renderHelp(w, rec, tok, true)
}

func (h *Handler) handleDel(w http.ResponseWriter, r *http.Request, user, peer string) {
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
