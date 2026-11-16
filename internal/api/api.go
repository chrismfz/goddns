// Package api is goddns's machine API, /api/v1/..., served on the DDNS
// listener. It is a thin JSON front-end over internal/service, like the
// admin UI: the service enforces role and zone grants; this package adds
// only what is specific to machines — bearer-token authentication, a scope
// per endpoint, rate limits and JSON.
//
// Auth: "Authorization: Bearer gdapi_..." (never in the URL — it would end
// up in proxy and access logs). A token acts as its owner login, narrowed by
// its scopes; see service.AuthenticateAPI.
package api

import (
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/service"
)

// Handler serves /api/v1/.
type Handler struct {
	svc *service.Service
	// clientIP resolves the caller's address the way the DDNS endpoint does
	// (trusted proxies / tls_mode none), for token CIDR checks and audit.
	clientIP func(*http.Request) net.IP

	mu      sync.Mutex
	fails   map[string]*failState // auth failures per source address
	buckets map[string]*bucket    // request rate per token
}

// bucket is a token bucket: reqPerSec refill, 2*reqPerSec burst.
type bucket struct {
	tokens float64
	last   time.Time
}

type failState struct {
	n     int
	until time.Time
	seen  time.Time
}

// Per-token request rate (burst 2x), and the auth-failure lockout per source.
const (
	reqPerSec    = 10
	failLimit    = 10               // failures before a source is locked out
	failWindow   = 10 * time.Minute // failures older than this are forgotten
	failLockout  = 5 * time.Minute
	maxBodyBytes = 64 << 10
)

// New builds the API handler.
func New(svc *service.Service, clientIP func(*http.Request) net.IP) *Handler {
	return &Handler{svc: svc, clientIP: clientIP, fails: map[string]*failState{}, buckets: map[string]*bucket{}}
}

type ctxActor struct {
	a      service.Actor
	scopes []string
}

// endpoint is one route: the scope it needs and the function serving it.
type endpoint func(w http.ResponseWriter, r *http.Request, c ctxActor)

// heavy marks an endpoint that does a zone transfer (AXFR) or a zone write
// behind one cheap request; it also spends from a much smaller budget.
const heavy = true

// Expensive endpoints: 1 per second per token, burst 3.
const heavyPerSec = 1

// Mux returns the routes, mounted under /api/v1/.
func (h *Handler) Mux() http.Handler {
	mux := http.NewServeMux()
	route := func(pattern, scope string, fn endpoint, heavy ...bool) {
		mux.HandleFunc(pattern, h.auth(scope, len(heavy) > 0 && heavy[0], fn))
	}
	route("GET /api/v1/me", "", h.me)
	route("GET /api/v1/zones", service.ScopeZonesRead, h.zones)
	route("GET /api/v1/zones/{zone}", service.ScopeZonesRead, h.zone, heavy)
	route("GET /api/v1/zones/{zone}/history", service.ScopeZonesRead, h.history)
	route("POST /api/v1/zones/{zone}/records", service.ScopeRecordsWrite, h.record, heavy)
	route("POST /api/v1/zones/{zone}/restore", service.ScopeRecordsWrite, h.restore, heavy)
	route("GET /api/v1/ddns", service.ScopeDDNSRead, h.ddnsList)
	route("POST /api/v1/ddns", service.ScopeDDNSWrite, h.ddnsAdd)
	route("POST /api/v1/ddns/{fqdn}/rotate", service.ScopeDDNSWrite, h.ddnsRotate)
	route("DELETE /api/v1/ddns/{fqdn}", service.ScopeDDNSWrite, h.ddnsDel)
	route("GET /api/v1/vhosts", service.ScopeProxyRead, h.vhosts)
	route("PUT /api/v1/vhosts/{host}", service.ScopeProxyWrite, h.vhostSet)
	route("DELETE /api/v1/vhosts/{host}", service.ScopeProxyWrite, h.vhostDel)
	route("GET /api/v1/users", service.ScopeUsersAdmin, h.users)
	route("PUT /api/v1/users/{user}/zones/{zone}", service.ScopeUsersAdmin, h.grant)
	route("DELETE /api/v1/users/{user}/zones/{zone}", service.ScopeUsersAdmin, h.revoke)
	mux.HandleFunc("/api/v1/", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, http.StatusNotFound, "no such endpoint")
	})
	return mux
}

// auth authenticates the bearer token, applies the failure lockout and the
// per-token rate limit, and checks the endpoint's scope ("" = any token).
func (h *Handler) auth(scope string, expensive bool, fn endpoint) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		ip := h.clientIP(r)
		if ip == nil {
			// e.g. a unix-socket proxy that sends no X-Forwarded-For: such
			// requests can't be attributed (CIDR checks, lockout, audit), and
			// pooling them under one key would let one bad client lock out all
			writeErr(w, http.StatusBadRequest, "no client address: the reverse proxy must send X-Forwarded-For")
			return
		}
		src := sourceKey(ip)
		if h.lockedOut(src) {
			w.Header().Set("Retry-After", strconv.Itoa(int(failLockout.Seconds())))
			writeErr(w, http.StatusTooManyRequests, "too many failed authentications — wait and retry")
			return
		}
		tok, ok := bearer(r)
		if !ok {
			h.failed(src)
			w.Header().Set("WWW-Authenticate", `Bearer realm="goddns"`)
			writeErr(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		a, scopes, err := h.svc.AuthenticateAPI(tok, ip)
		if err != nil {
			h.failed(src)
			w.Header().Set("WWW-Authenticate", `Bearer realm="goddns", error="invalid_token"`)
			writeErr(w, http.StatusUnauthorized, "invalid token")
			return
		}
		key := a.Via + "|" + a.User
		if !h.allow(key, reqPerSec) || (expensive && !h.allow("heavy|"+key, heavyPerSec)) {
			w.Header().Set("Retry-After", "1")
			writeErr(w, http.StatusTooManyRequests, "rate limit")
			return
		}
		if scope != "" && !service.HasScope(scopes, scope) {
			writeErr(w, http.StatusForbidden, "this token lacks the "+scope+" scope")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		fn(w, r, ctxActor{a: a, scopes: scopes})
	}
}

// sourceKey buckets auth failures by source: an IPv4 address, or the /64 of
// an IPv6 one (a single host usually holds a whole /64 and could otherwise
// rotate addresses to dodge the lockout — the proxy limiter's lesson).
func sourceKey(ip net.IP) string {
	switch {
	case ip == nil:
		return "?"
	case ip.To4() != nil:
		return ip.String()
	default:
		return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
	}
}

func bearer(r *http.Request) (string, bool) {
	v := r.Header.Get("Authorization")
	if len(v) < 7 || !strings.EqualFold(v[:7], "bearer ") {
		return "", false
	}
	t := strings.TrimSpace(v[7:])
	return t, t != ""
}

func (h *Handler) lockedOut(src string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	f := h.fails[src]
	return f != nil && time.Now().Before(f.until)
}

func (h *Handler) failed(src string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	f := h.fails[src]
	if f == nil || now.Sub(f.seen) > failWindow {
		f = &failState{}
		h.fails[src] = f
	}
	f.n++
	f.seen = now
	if f.n >= failLimit {
		f.until, f.n = now.Add(failLockout), 0
	}
	if len(h.fails) > 10000 { // bound memory under a wide scan
		for k, v := range h.fails {
			if now.Sub(v.seen) > failWindow && now.After(v.until) {
				delete(h.fails, k)
			}
		}
	}
}

// allow takes one request from key's bucket (perSec refill, burst
// 2*perSec, at least 3). Keys are tokens, so the map is bounded by the
// number of tokens that exist.
func (h *Handler) allow(key string, perSec float64) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	burst := max(2*perSec, 3)
	b := h.buckets[key]
	if b == nil {
		b = &bucket{tokens: burst, last: now}
		h.buckets[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * perSec
	if b.tokens > burst {
		b.tokens = burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// --- JSON helpers ---

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// writeOpErr maps a service error to a status. A caller mistake says what
// was wrong (400); any other failure is a 500, with the detail (paths,
// command output, BIND's answer) in the server log and, for an admin token,
// in the response — a user-role token gets a generic message.
func writeOpErr(w http.ResponseWriter, c ctxActor, err error) {
	switch {
	case service.IsForbidden(err):
		writeErr(w, http.StatusForbidden, "forbidden")
	case service.IsInvalid(err):
		writeErr(w, http.StatusBadRequest, err.Error())
	default:
		log.Printf("api: user=%s via=%s: %v", c.a.User, c.a.Via, err)
		msg := "operation failed (details in the server log)"
		if c.a.Role == service.RoleAdmin {
			msg = err.Error()
		}
		writeErr(w, http.StatusInternalServerError, msg)
	}
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeErr(w, http.StatusRequestEntityTooLarge, "body too large")
		} else {
			writeErr(w, http.StatusBadRequest, "bad JSON body: "+err.Error())
		}
		return false
	}
	return true
}

// --- endpoints ---

func (h *Handler) me(w http.ResponseWriter, r *http.Request, c ctxActor) {
	zones, _ := h.svc.MyZones(c.a)
	writeJSON(w, http.StatusOK, map[string]any{
		"user": c.a.User, "role": c.a.Role, "token": strings.TrimPrefix(c.a.Via, "api:"),
		"scopes": c.scopes, "zones": zones,
	})
}

type zoneJSON struct {
	Name    string `json:"name"`
	View    string `json:"view,omitempty"`
	Kind    string `json:"kind"`
	Dynamic bool   `json:"dynamic"`
}

func (h *Handler) zones(w http.ResponseWriter, r *http.Request, c ctxActor) {
	zl, err := h.svc.Zones(c.a)
	if err != nil {
		writeOpErr(w, c, err)
		return
	}
	out := make([]zoneJSON, 0, len(zl.Zones))
	for _, z := range zl.Zones {
		out = append(out, zoneJSON{Name: z.Name, View: z.View, Kind: z.Kind(), Dynamic: z.Dynamic})
	}
	writeJSON(w, http.StatusOK, map[string]any{"zones": out})
}

type rrJSON struct {
	Name string `json:"name"`
	TTL  uint32 `json:"ttl"`
	Type string `json:"type"`
	Data string `json:"data"`
}

func (h *Handler) zone(w http.ResponseWriter, r *http.Request, c ctxActor) {
	name := service.NormZone(r.PathValue("zone"))
	v, err := h.svc.Zone(c.a, name, false)
	if err != nil {
		writeOpErr(w, c, err)
		return
	}
	var rrs []rrJSON
	for _, rr := range v.Records {
		hd := rr.Header()
		rrs = append(rrs, rrJSON{Name: hd.Name, TTL: hd.Ttl, Type: dns.TypeToString[hd.Rrtype],
			Data: strings.TrimSpace(strings.TrimPrefix(rr.String(), hd.String()))})
	}
	out := map[string]any{"zone": name, "editable": v.Editable, "in_place": v.FileEdit, "records": rrs}
	if v.Conf != nil {
		out["kind"], out["dynamic"] = v.Conf.Kind(), v.Conf.Dynamic
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) history(w http.ResponseWriter, r *http.Request, c ctxActor) {
	hist, err := h.svc.History(c.a, service.NormZone(r.PathValue("zone")))
	if err != nil {
		writeOpErr(w, c, err)
		return
	}
	type snap struct {
		ID      int64     `json:"id"`
		Serial  uint32    `json:"serial"`
		TakenAt time.Time `json:"taken_at"`
	}
	snaps := make([]snap, 0, len(hist.Snapshots))
	for _, sn := range hist.Snapshots {
		snaps = append(snaps, snap{sn.ID, sn.Serial, sn.TakenAt})
	}
	out := map[string]any{"zone": hist.Name, "restorable": hist.Restorable, "snapshots": snaps}
	if hist.HasDiff {
		out["last_change"] = map[string]any{"from_serial": hist.FromSerial, "to_serial": hist.ToSerial,
			"added": hist.Added, "removed": hist.Removed}
	}
	writeJSON(w, http.StatusOK, out)
}

// record: {"action":"add"|"del", "rr":"www 300 IN A 192.0.2.1", "dry_run":true}
func (h *Handler) record(w http.ResponseWriter, r *http.Request, c ctxActor) {
	var in struct {
		Action string `json:"action"`
		RR     string `json:"rr"`
		DryRun bool   `json:"dry_run"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	res, err := h.svc.EditRecord(c.a, r.PathValue("zone"), in.Action, in.RR, !in.DryRun)
	if err != nil {
		writeOpErr(w, c, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"zone": res.Zone, "applied": !in.DryRun,
		"added": res.Added, "removed": res.Removed, "in_place": res.Static, "serial": res.Serial, "snapshot": res.Snapshot})
}

// restore: {"id": 42, "dry_run": true}
func (h *Handler) restore(w http.ResponseWriter, r *http.Request, c ctxActor) {
	var in struct {
		ID     int64 `json:"id"`
		DryRun bool  `json:"dry_run"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	res, err := h.svc.Restore(c.a, r.PathValue("zone"), in.ID, !in.DryRun)
	if err != nil {
		writeOpErr(w, c, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"zone": res.Zone, "applied": !in.DryRun, "snapshot": res.Snapshot.ID,
		"added": res.Added, "removed": res.Removed, "pre_snapshot": res.PreSnapshot})
}

type ddnsJSON struct {
	FQDN       string    `json:"fqdn"`
	Zone       string    `json:"zone"`
	TTL        uint32    `json:"ttl"`
	LastIP     string    `json:"last_ip,omitempty"`
	LastUpdate time.Time `json:"last_update,omitzero"`
	LastSeen   time.Time `json:"last_seen,omitzero"`
	Disabled   bool      `json:"disabled"`
	Token      string    `json:"token,omitempty"` // only right after add / rotate
}

func (h *Handler) ddnsList(w http.ResponseWriter, r *http.Request, c ctxActor) {
	recs, err := h.svc.DDNSList(c.a)
	if err != nil {
		writeOpErr(w, c, err)
		return
	}
	out := make([]ddnsJSON, 0, len(recs))
	for _, rec := range recs {
		out = append(out, ddnsJSON{FQDN: rec.FQDN, Zone: rec.Zone, TTL: rec.TTL, LastIP: rec.LastIP,
			LastUpdate: nonEpoch(rec.LastUpdate), LastSeen: nonEpoch(rec.LastSeen), Disabled: rec.Disabled})
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": out})
}

// ddnsAdd: {"fqdn":"home", "zone":"ddns.example.com", "ttl":60} → the token, once.
func (h *Handler) ddnsAdd(w http.ResponseWriter, r *http.Request, c ctxActor) {
	var in struct {
		FQDN string `json:"fqdn"`
		Zone string `json:"zone"`
		TTL  int    `json:"ttl"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	rec, tok, err := h.svc.DDNSAdd(c.a, in.FQDN, in.Zone, in.TTL)
	if err != nil {
		writeOpErr(w, c, err)
		return
	}
	writeJSON(w, http.StatusCreated, ddnsJSON{FQDN: rec.FQDN, Zone: rec.Zone, TTL: rec.TTL, Token: tok})
}

func (h *Handler) ddnsRotate(w http.ResponseWriter, r *http.Request, c ctxActor) {
	rec, tok, err := h.svc.DDNSRotate(c.a, r.PathValue("fqdn"))
	if err != nil {
		writeOpErr(w, c, err)
		return
	}
	writeJSON(w, http.StatusOK, ddnsJSON{FQDN: rec.FQDN, Zone: rec.Zone, TTL: rec.TTL, Token: tok})
}

func (h *Handler) ddnsDel(w http.ResponseWriter, r *http.Request, c ctxActor) {
	if err := h.svc.DDNSDel(c.a, r.PathValue("fqdn")); err != nil {
		writeOpErr(w, c, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type vhostJSON struct {
	Host           string   `json:"host,omitempty"`
	Managed        bool     `json:"managed"`
	Upstream       string   `json:"upstream"`
	UpstreamVerify bool     `json:"upstream_verify,omitempty"`
	PreserveHost   bool     `json:"preserve_host,omitempty"`
	BMCCompat      bool     `json:"bmc_compat,omitempty"`
	ConsolePorts   []int    `json:"console_ports,omitempty"`
	Allow          []string `json:"allow,omitempty"`
	RateLimit      int      `json:"rate_limit,omitempty"`
	BasicAuth      []string `json:"basic_auth,omitempty"` // "user:bcrypt" entries (hashes, never passwords)
}

func (v vhostJSON) rule() config.ProxyRule {
	return config.ProxyRule{Upstream: v.Upstream, UpstreamVerify: v.UpstreamVerify, PreserveHost: v.PreserveHost,
		BMCCompat: v.BMCCompat, ConsolePorts: v.ConsolePorts, Allow: v.Allow, RateLimit: v.RateLimit, BasicAuth: v.BasicAuth}
}

func (h *Handler) vhosts(w http.ResponseWriter, r *http.Request, c ctxActor) {
	es, err := h.svc.VhostList(c.a)
	if err != nil {
		writeOpErr(w, c, err)
		return
	}
	out := make([]vhostJSON, 0, len(es))
	for _, e := range es {
		ru := e.Rule
		out = append(out, vhostJSON{Host: e.Host, Managed: e.Managed, Upstream: ru.Upstream, UpstreamVerify: ru.UpstreamVerify,
			PreserveHost: ru.PreserveHost, BMCCompat: ru.BMCCompat, ConsolePorts: ru.ConsolePorts, Allow: ru.Allow,
			RateLimit: ru.RateLimit, BasicAuth: ru.BasicAuth})
	}
	writeJSON(w, http.StatusOK, map[string]any{"vhosts": out})
}

// vhostSet: PUT /api/v1/vhosts/{host}?dry_run=1 with the rule as the body.
func (h *Handler) vhostSet(w http.ResponseWriter, r *http.Request, c ctxActor) {
	var in vhostJSON
	if !readJSON(w, r, &in) {
		return
	}
	dry := r.URL.Query().Get("dry_run") == "1"
	res, err := h.svc.VhostSet(c.a, r.PathValue("host"), in.rule(), !dry)
	if err != nil {
		writeOpErr(w, c, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"host": res.Host, "action": res.Action, "applied": !dry, "fragment": res.Fragment})
}

func (h *Handler) vhostDel(w http.ResponseWriter, r *http.Request, c ctxActor) {
	dry := r.URL.Query().Get("dry_run") == "1"
	res, err := h.svc.VhostRemove(c.a, r.PathValue("host"), !dry)
	if err != nil {
		writeOpErr(w, c, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"host": res.Host, "action": res.Action, "applied": !dry})
}

func (h *Handler) users(w http.ResponseWriter, r *http.Request, c ctxActor) {
	us, err := h.svc.Users(c.a)
	if err != nil {
		writeOpErr(w, c, err)
		return
	}
	type userJSON struct {
		Name     string   `json:"name"`
		Role     string   `json:"role"`
		Disabled bool     `json:"disabled"`
		Source   string   `json:"source"`
		Zones    []string `json:"zones"`
	}
	out := make([]userJSON, 0, len(us))
	for _, u := range us {
		src := "db"
		if u.Config {
			src = "goddns.conf"
		}
		out = append(out, userJSON{Name: u.Name, Role: u.Role, Disabled: u.Disabled, Source: src, Zones: u.Zones})
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": out})
}

func (h *Handler) grant(w http.ResponseWriter, r *http.Request, c ctxActor) {
	if err := h.svc.Grant(c.a, r.PathValue("user"), r.PathValue("zone")); err != nil {
		writeOpErr(w, c, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) revoke(w http.ResponseWriter, r *http.Request, c ctxActor) {
	if err := h.svc.Revoke(c.a, r.PathValue("user"), r.PathValue("zone")); err != nil {
		writeOpErr(w, c, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func nonEpoch(t time.Time) time.Time {
	if t.Unix() <= 0 {
		return time.Time{}
	}
	return t
}
