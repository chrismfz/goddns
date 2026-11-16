package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/filezone"
	"github.com/chrismfz/goddns/internal/named"
	"github.com/chrismfz/goddns/internal/service"
	"github.com/chrismfz/goddns/internal/store"
	"github.com/chrismfz/goddns/internal/zonemgr"
)

type fixture struct {
	cfg   *config.Config
	svc   *service.Service
	st    *store.Store
	h     http.Handler
	audit *[]string
	peer  string
}

var admin = service.Actor{User: "cli:test", Peer: "local", Role: service.RoleAdmin}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	conf := filepath.Join(dir, "goddns.conf")
	os.WriteFile(conf, []byte("cert_file = \"/tmp/c\"\nkey_file = \"/tmp/k\"\n"), 0o600)
	cfg, err := config.Load(conf)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	svc := service.New(func() *config.Config { return cfg }, st)
	inv := &named.Inventory{Zones: []named.Zone{ // dynamic: DDNS lives in them
		{Name: "example.com", Type: "master", Path: "/x/example.com.db", Dynamic: true},
		{Name: "other.net", Type: "master", Path: "/x/other.net.db", Dynamic: true},
	}}
	svc.Inv = func(*config.Config) (*named.Inventory, error) { return inv, nil }
	var lines []string
	svc.Logf = func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) }
	f := &fixture{cfg: cfg, svc: svc, st: st, audit: &lines, peer: "203.0.113.10"}
	f.h = New(svc, func(r *http.Request) net.IP { return net.ParseIP(f.peer) }).Mux()
	return f
}

func (f *fixture) do(t *testing.T, method, path, tok, body string) (int, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rd)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	rr := httptest.NewRecorder()
	f.h.ServeHTTP(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

func (f *fixture) userWithToken(t *testing.T, name string, scopes []string, nets []string) string {
	t.Helper()
	if err := f.svc.UserAdd(admin, name, name+"pass123", service.RoleUser); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Grant(admin, name, "example.com"); err != nil {
		t.Fatal(err)
	}
	_, tok, err := f.svc.APITokenCreate(admin, name, "ci", scopes, nets, 0)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestAPIAuthAndScopes(t *testing.T) {
	f := newFixture(t)
	tok := f.userWithToken(t, "alice", []string{service.ScopeZonesRead, service.ScopeDDNSWrite}, nil)

	if code, _ := f.do(t, "GET", "/api/v1/me", "", ""); code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", code)
	}
	if code, _ := f.do(t, "GET", "/api/v1/me", "gdapi_bogus", ""); code != http.StatusUnauthorized {
		t.Fatalf("bad token: %d", code)
	}
	code, me := f.do(t, "GET", "/api/v1/me", tok, "")
	if code != 200 || me["user"] != "alice" || me["role"] != "user" || me["token"] != "ci" {
		t.Fatalf("me: %d %v", code, me)
	}
	// zones: only the granted one
	code, zl := f.do(t, "GET", "/api/v1/zones", tok, "")
	if zs, _ := zl["zones"].([]any); code != 200 || len(zs) != 1 || zs[0].(map[string]any)["name"] != "example.com" {
		t.Fatalf("zones: %d %v", code, zl)
	}
	// scope missing → 403 even though alice could do it in the UI
	if code, out := f.do(t, "POST", "/api/v1/zones/example.com/records", tok, `{"action":"add","rr":"x 60 IN A 1.2.3.4"}`); code != 403 || !strings.Contains(fmt.Sprint(out["error"]), "records:write") {
		t.Fatalf("records without scope: %d %v", code, out)
	}
	// grant enforced behind the scope
	if code, _ := f.do(t, "GET", "/api/v1/zones/other.net/history", tok, ""); code != 403 {
		t.Fatalf("ungranted zone: %d", code)
	}
	// DDNS add in the granted zone, relative name, token in the response
	code, add := f.do(t, "POST", "/api/v1/ddns", tok, `{"fqdn":"cam","zone":"example.com"}`)
	if code != 201 || add["fqdn"] != "cam.example.com." || add["token"] == "" {
		t.Fatalf("ddns add: %d %v", code, add)
	}
	// ddns:read is a separate scope
	if code, _ := f.do(t, "GET", "/api/v1/ddns", tok, ""); code != 403 {
		t.Fatalf("ddns list without ddns:read: %d", code)
	}
	// admin-only endpoints: a user token can't even hold the scope
	if _, _, err := f.svc.APITokenCreate(admin, "alice", "x", []string{service.ScopeUsersAdmin}, nil, 0); !service.IsInvalid(err) {
		t.Fatalf("users:admin on a user-role token: %v", err)
	}
	// unknown fields and unknown routes
	if code, _ := f.do(t, "POST", "/api/v1/ddns", tok, `{"fqdn":"a","zone":"example.com","owner":"bob"}`); code != 400 {
		t.Fatalf("unknown JSON field: %d", code)
	}
	if code, _ := f.do(t, "GET", "/api/v1/nope", tok, ""); code != 404 {
		t.Fatalf("unknown route: %d", code)
	}
	// the audit names the token
	found := false
	for _, l := range *f.audit {
		if strings.Contains(l, "user=alice via=api:ci peer=203.0.113.10 ddns-add") {
			found = true
		}
	}
	if !found {
		t.Fatalf("audit: %v", *f.audit)
	}
}

func TestAPITokenFollowsItsLogin(t *testing.T) {
	f := newFixture(t)
	tok := f.userWithToken(t, "bob", []string{service.ScopeZonesRead}, nil)
	if code, _ := f.do(t, "GET", "/api/v1/zones/example.com/history", tok, ""); code == 401 || code == 403 {
		t.Fatalf("granted: %d", code)
	}
	f.svc.Revoke(admin, "bob", "example.com")
	if code, _ := f.do(t, "GET", "/api/v1/zones/example.com/history", tok, ""); code != 403 {
		t.Fatalf("after revoke: %d", code)
	}
	f.svc.UserSetDisabled(admin, "bob", true)
	if code, _ := f.do(t, "GET", "/api/v1/me", tok, ""); code != 401 {
		t.Fatalf("disabled owner: %d", code)
	}
	f.svc.UserSetDisabled(admin, "bob", false)
	f.svc.UserDel(admin, "bob")
	if code, _ := f.do(t, "GET", "/api/v1/me", tok, ""); code != 401 {
		t.Fatalf("deleted owner: %d", code)
	}
}

func TestAPITokenCIDRAndExpiry(t *testing.T) {
	f := newFixture(t)
	tok := f.userWithToken(t, "carol", []string{service.ScopeZonesRead}, []string{"198.51.100.0/24"})
	if code, _ := f.do(t, "GET", "/api/v1/me", tok, ""); code != 401 {
		t.Fatalf("outside allow: %d", code)
	}
	f.peer = "198.51.100.9"
	if code, _ := f.do(t, "GET", "/api/v1/me", tok, ""); code != 200 {
		t.Fatalf("inside allow: %d", code)
	}
}

func TestAPIFailureLockoutAndRateLimit(t *testing.T) {
	f := newFixture(t)
	tok := f.userWithToken(t, "dave", []string{service.ScopeZonesRead}, nil)
	f.peer = "192.0.2.50"
	for i := 0; i < failLimit; i++ {
		f.do(t, "GET", "/api/v1/me", "gdapi_wrong", "")
	}
	if code, _ := f.do(t, "GET", "/api/v1/me", tok, ""); code != 429 {
		t.Fatalf("locked-out source with a good token: %d", code)
	}
	f.peer = "2001:db8:1:2::1" // another /64 is not locked out
	if code, _ := f.do(t, "GET", "/api/v1/me", tok, ""); code != 200 {
		t.Fatalf("other source: %d", code)
	}
	limited := false
	for i := 0; i < 5*reqPerSec; i++ {
		if code, _ := f.do(t, "GET", "/api/v1/me", tok, ""); code == 429 {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("per-token rate limit never applied")
	}
}

func TestAPIAdminAndMinting(t *testing.T) {
	f := newFixture(t)
	f.svc.UserAdd(admin, "root2", "rootpass12", service.RoleAdmin)
	_, tok, err := f.svc.APITokenCreate(admin, "root2", "ops", []string{service.ScopeUsersAdmin, service.ScopeZonesRead}, nil, 30)
	if err != nil {
		t.Fatal(err)
	}
	f.svc.UserAdd(admin, "erin", "erinpass12", service.RoleUser)
	if code, _ := f.do(t, "PUT", "/api/v1/users/erin/zones/other.net", tok, ""); code != 204 {
		t.Fatalf("grant via API: %d", code)
	}
	code, us := f.do(t, "GET", "/api/v1/users", tok, "")
	if code != 200 || !strings.Contains(fmt.Sprint(us), "other.net") {
		t.Fatalf("users: %d %v", code, us)
	}
	// an API-authenticated actor can't mint tokens (a leaked token can't make itself permanent)
	apiActor := service.Actor{User: "root2", Role: service.RoleAdmin, Via: "api:ops"}
	if _, _, err := f.svc.APITokenCreate(apiActor, "root2", "more", []string{service.ScopeZonesRead}, nil, 0); !service.IsForbidden(err) {
		t.Fatalf("token minting via API: %v", err)
	}
	// a user can't manage someone else's tokens
	user := service.Actor{User: "erin", Role: service.RoleUser}
	if _, _, err := f.svc.APITokenCreate(user, "root2", "x", []string{service.ScopeZonesRead}, nil, 0); !service.IsForbidden(err) {
		t.Fatalf("user minting for another login: %v", err)
	}
	ts, _ := f.svc.APITokens(admin, "")
	if err := f.svc.APITokenRevoke(user, ts[0].ID); !service.IsForbidden(err) {
		t.Fatalf("user revoking another's token: %v", err)
	}
	if err := f.svc.APITokenRevoke(admin, ts[0].ID); err != nil {
		t.Fatal(err)
	}
	if code, _ := f.do(t, "GET", "/api/v1/me", tok, ""); code != 401 {
		t.Fatalf("revoked token: %d", code)
	}
}

// staticZone wires example.com as an editable static zone file.
func (f *fixture) staticZone(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	zp := filepath.Join(dir, "example.com.db")
	os.WriteFile(zp, []byte("$ORIGIN example.com.\n$TTL 60\n@ IN SOA ns.example.com. h.example.com. 1 3 4 5 6\n@ IN NS ns.example.com.\n"), 0o640)
	inv := &named.Inventory{Zones: []named.Zone{
		{Name: "example.com", Type: "master", Path: zp},
		{Name: "other.net", Type: "master", Path: "/x/other.net.db"},
	}}
	f.svc.Inv = func(*config.Config) (*named.Inventory, error) { return inv, nil }
	f.svc.FileEd = func(*config.Config) *filezone.Editor {
		return &filezone.Editor{Editable: []string{"example.com"}, LockDir: filepath.Join(dir, "l"), BackupDir: filepath.Join(dir, "b"),
			Inv: func() (*named.Inventory, error) { return inv, nil }, CheckZone: func(string, []byte) error { return nil },
			Reload: func(string) error { return nil }, Verify: func(string, uint32) error { return nil }}
	}
	return zp
}

func TestAPIRecordWriteDryRunThenApply(t *testing.T) {
	f := newFixture(t)
	zp := f.staticZone(t)
	tok := f.userWithToken(t, "gina", []string{service.ScopeRecordsWrite}, nil)
	body := `{"action":"add","rr":"www.example.com 60 IN A 192.0.2.80","dry_run":true}`
	code, out := f.do(t, "POST", "/api/v1/zones/example.com/records", tok, body)
	if code != 200 || out["applied"] != false || !strings.Contains(fmt.Sprint(out["added"]), "www.example.com.") {
		t.Fatalf("dry run: %d %v", code, out)
	}
	if b, _ := os.ReadFile(zp); strings.Contains(string(b), "192.0.2.80") {
		t.Fatal("dry run wrote the zone")
	}
	code, out = f.do(t, "POST", "/api/v1/zones/example.com/records", tok, strings.Replace(body, "true", "false", 1))
	if code != 200 || out["applied"] != true {
		t.Fatalf("apply: %d %v", code, out)
	}
	if b, _ := os.ReadFile(zp); !strings.Contains(string(b), "192.0.2.80") {
		t.Fatal("apply did not write the zone")
	}
}

func TestAPIVhosts(t *testing.T) {
	f := newFixture(t)
	dir := t.TempDir()
	conf := filepath.Join(dir, "goddns.conf")
	os.WriteFile(conf, []byte(""), 0o600)
	f.svc.ConfPath = conf
	f.svc.UserAdd(admin, "hank", "hankpass12", service.RoleAdmin)
	_, tok, _ := f.svc.APITokenCreate(admin, "hank", "px", []string{service.ScopeProxyRead, service.ScopeProxyWrite}, nil, 0)
	code, out := f.do(t, "PUT", "/api/v1/vhosts/nas.example.com?dry_run=1", tok, `{"upstream":"http://10.0.0.5:80","allow":["10.0.0.0/8"]}`)
	if code != 200 || out["applied"] != false || !strings.Contains(fmt.Sprint(out["fragment"]), "10.0.0.5") {
		t.Fatalf("vhost dry run: %d %v", code, out)
	}
	if code, _ := f.do(t, "PUT", "/api/v1/vhosts/nas.example.com", tok, `{"upstream":"http://10.0.0.5:80"}`); code != 200 {
		t.Fatalf("vhost set: %d", code)
	}
	code, out = f.do(t, "GET", "/api/v1/vhosts", tok, "")
	if code != 200 || !strings.Contains(fmt.Sprint(out["vhosts"]), "nas.example.com") {
		t.Fatalf("vhosts: %d %v", code, out)
	}
	if code, _ := f.do(t, "DELETE", "/api/v1/vhosts/nas.example.com", tok, ""); code != 200 {
		t.Fatalf("vhost del: %d", code)
	}
}

func TestAPIHeavyBudgetAndUnattributable(t *testing.T) {
	f := newFixture(t)
	tok := f.userWithToken(t, "ivy", []string{service.ScopeZonesRead}, nil)
	limited := false
	for i := 0; i < 10; i++ { // AXFR-backed: burst 3, then 1/s
		if code, _ := f.do(t, "GET", "/api/v1/zones/example.com", tok, ""); code == 429 {
			limited = i >= 3
			break
		}
	}
	if !limited {
		t.Fatal("AXFR-backed endpoint not on the tighter budget")
	}
	if code, _ := f.do(t, "GET", "/api/v1/zones", tok, ""); code != 200 { // cheap endpoints keep their own budget
		t.Fatalf("cheap endpoint after heavy limit: %d", code)
	}
	f.peer = "" // no resolvable client address
	if code, _ := f.do(t, "GET", "/api/v1/me", tok, ""); code != 400 {
		t.Fatalf("unattributable request: %d", code)
	}
}

func TestAPITokenCapAndUserErrorText(t *testing.T) {
	f := newFixture(t)
	f.svc.UserAdd(admin, "jo", "jopass1234", service.RoleUser)
	for i := 0; i < service.MaxAPITokensPerUser; i++ {
		if _, _, err := f.svc.APITokenCreate(admin, "jo", fmt.Sprintf("t%d", i), []string{service.ScopeZonesRead}, nil, 0); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := f.svc.APITokenCreate(admin, "jo", "one-more", []string{service.ScopeZonesRead}, nil, 0); !service.IsInvalid(err) {
		t.Fatalf("token cap: %v", err)
	}
	// an internal failure: generic text for a user token, 500 not 502
	f.svc.Grant(admin, "jo", "example.com")
	ts, _ := f.svc.APITokens(admin, "jo")
	if err := f.svc.APITokenRevoke(admin, ts[0].ID); err != nil { // make room
		t.Fatal(err)
	}
	_, tok, err := f.svc.APITokenCreate(admin, "jo", "z2", []string{service.ScopeZonesRead}, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.svc.Inv = func(*config.Config) (*named.Inventory, error) {
		return nil, fmt.Errorf("named-checkconf -p: /etc/named.conf:12: secret detail")
	}
	code, out := f.do(t, "GET", "/api/v1/zones", tok, "")
	if code != 500 || strings.Contains(fmt.Sprint(out["error"]), "secret detail") {
		t.Fatalf("user-facing internal error: %d %v", code, out)
	}
}

func TestAPIZoneCreateDelete(t *testing.T) {
	f := newFixture(t)
	dir := t.TempDir()
	nc, inc := filepath.Join(dir, "named.conf"), filepath.Join(dir, "goddns-zones.conf")
	os.WriteFile(nc, []byte("include \""+inc+"\";\n"), 0o644)
	f.cfg.ManagedInclude = inc
	inv := &named.Inventory{Zones: []named.Zone{{Name: "example.com", Type: "master"}}}
	f.svc.ZoneMgr = func(*config.Config) *zonemgr.Manager {
		return &zonemgr.Manager{NamedConf: nc, Include: inc, ZoneDir: filepath.Join(dir, "z"), LockDir: filepath.Join(dir, "l"),
			Inv: func() (*named.Inventory, error) { return inv, nil }, CheckZone: func(string, []byte) error { return nil },
			CheckConf: func() error { return nil }, Reconfig: func() error { return nil }, Verify: func(string) error { return nil }}
	}
	f.svc.UserAdd(admin, "max", "maxpass123", service.RoleAdmin)
	_, tok, _ := f.svc.APITokenCreate(admin, "max", "zones", []string{service.ScopeZonesAdmin}, nil, 0)
	code, out := f.do(t, "POST", "/api/v1/zones", tok, `{"zone":"new.example.org","ns":["ns1.example.com"],"dry_run":true}`)
	if code != 200 || out["applied"] != false || !strings.Contains(fmt.Sprint(out["content"]), "SOA") {
		t.Fatalf("dry run: %d %v", code, out)
	}
	if code, out := f.do(t, "POST", "/api/v1/zones", tok, `{"zone":"new.example.org","ns":["ns1.example.com"]}`); code != 201 {
		t.Fatalf("create: %d %v", code, out)
	}
	// a second token: the zone endpoints spend from the 1/s (burst 3) budget
	_, tok, _ = f.svc.APITokenCreate(admin, "max", "zones2", []string{service.ScopeZonesAdmin}, nil, 0)
	if code, out := f.do(t, "DELETE", "/api/v1/zones/example.com", tok, ""); code != 400 || !strings.Contains(fmt.Sprint(out["error"]), "defined elsewhere") {
		t.Fatalf("delete an operator zone: %d %v", code, out)
	}
	if code, _ := f.do(t, "DELETE", "/api/v1/zones/new.example.org", tok, ""); code != 200 {
		t.Fatalf("delete: %d", code)
	}
	// a user-role token can't hold zones:admin
	f.svc.UserAdd(admin, "ned", "nedpass123", service.RoleUser)
	if _, _, err := f.svc.APITokenCreate(admin, "ned", "z", []string{service.ScopeZonesAdmin}, nil, 0); !service.IsInvalid(err) {
		t.Fatalf("zones:admin for a user: %v", err)
	}
}
