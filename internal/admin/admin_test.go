package admin

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/store"
)

func TestSessionRoundTrip(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	const fp = "$2a$10$hashfingerprint"
	look := func(u string) (string, bool) {
		if u == "chris" {
			return fp, true
		}
		return "", false
	}
	tok := newSession(secret, fp, "chris", time.Hour)
	if u, ok := parseSession(secret, tok, look); !ok || u != "chris" {
		t.Fatalf("valid session: %q %v", u, ok)
	}
	if _, ok := parseSession([]byte("different-key-different-key-1234"), tok, look); ok {
		t.Fatal("session verified under wrong key")
	}
	if _, ok := parseSession(secret, tok+"x", look); ok {
		t.Fatal("tampered session accepted")
	}
	// password change -> different fingerprint -> session invalid
	look2 := func(u string) (string, bool) { return "$2a$10$DIFFERENThash", u == "chris" }
	if _, ok := parseSession(secret, tok, look2); ok {
		t.Fatal("session survived a credential change")
	}
	// user removed -> lookup fails -> invalid
	if _, ok := parseSession(secret, tok, func(string) (string, bool) { return "", false }); ok {
		t.Fatal("session survived user removal")
	}
	exp := newSession(secret, fp, "chris", -time.Hour)
	if _, ok := parseSession(secret, exp, look); ok {
		t.Fatal("expired session accepted")
	}
}

func TestLoginThrottle(t *testing.T) {
	h, _ := newHandler(t, mkConfig(t, ""))
	// hammer wrong passwords from one IP until it locks
	locked := false
	for i := 0; i < throttleThreshold+2; i++ {
		rr := do(h, "POST", "/login", "203.0.113.9:1",
			map[string]string{"user": "admin", "pass": "wrong"}, nil)
		if rr.Code == http.StatusTooManyRequests {
			locked = true
			break
		}
	}
	if !locked {
		t.Fatal("login never throttled after repeated failures")
	}
	// a different IP is unaffected (gets normal 401, not 429)
	rr := do(h, "POST", "/login", "198.51.100.7:1",
		map[string]string{"user": "admin", "pass": "wrong"}, nil)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("fresh IP should not be pre-throttled: %d", rr.Code)
	}
}

func TestAdminAllowIgnoresXFF(t *testing.T) {
	// The admin CIDR gate must use the TCP peer, never a spoofable header.
	h, _ := newHandler(t, mkConfig(t, `allow = ["127.0.0.0/8"]`))
	req := httptest.NewRequest("GET", "/login", nil)
	req.RemoteAddr = "8.8.8.8:1" // outside allow
	req.Header.Set("X-Forwarded-For", "127.0.0.1")
	req.Header.Set("X-Real-IP", "127.0.0.1")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("XFF spoof bypassed admin allowlist: %d", rr.Code)
	}
}

func mkConfig(t *testing.T, extra string) *config.Config {
	t.Helper()
	hash, _ := bcrypt.GenerateFromPassword([]byte("s3cretpass"), bcrypt.MinCost)
	dir := t.TempDir()
	conf := filepath.Join(dir, "goddns.conf")
	body := `
cert_file = "/tmp/c.pem"
key_file  = "/tmp/k.pem"
proxy_enabled = true
[admin]
enabled = true
host = "admin.myip.gr"
users = ["admin:` + string(hash) + `"]
` + extra
	if err := os.WriteFile(conf, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := config.Load(conf)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return c
}

func newHandler(t *testing.T, c *config.Config) (*Handler, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	secret := []byte("0123456789abcdef0123456789abcdef")
	return New(func() *config.Config { return c }, st, secret, "test"), st
}

func do(h *Handler, method, target, remote string, form map[string]string, cookie *http.Cookie) *httptest.ResponseRecorder {
	var body strings.Reader
	if form != nil {
		vals := []string{}
		for k, v := range form {
			vals = append(vals, k+"="+v)
		}
		body = *strings.NewReader(strings.Join(vals, "&"))
	}
	req := httptest.NewRequest(method, target, &body)
	if remote != "" {
		req.RemoteAddr = remote
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func login(t *testing.T, h *Handler) *http.Cookie {
	t.Helper()
	rr := do(h, "POST", "/login", "127.0.0.1:1", map[string]string{"user": "admin", "pass": "s3cretpass"}, nil)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("login: %d", rr.Code)
	}
	for _, c := range rr.Result().Cookies() {
		if c.Name == cookieName {
			return c
		}
	}
	t.Fatal("no session cookie set")
	return nil
}

func TestZoneHistoryDiffAndEscaping(t *testing.T) {
	h, st := newHandler(t, mkConfig(t, ""))
	// Two snapshots: a record changes A -> TXT, and the new TXT rdata carries
	// an XSS payload (as a hostile panel client could).
	if _, err := st.SnapshotPut("evil.example", 1,
		"evil.example. 60 IN SOA ns. h. 1 3600 600 1209600 60\nx.evil.example. 60 IN A 1.1.1.1\n", 50); err != nil {
		t.Fatal(err)
	}
	if _, err := st.SnapshotPut("evil.example", 2,
		"evil.example. 60 IN SOA ns. h. 2 3600 600 1209600 60\nx.evil.example. 60 IN TXT \"</span><script>alert(1)</script>\"\n", 50); err != nil {
		t.Fatal(err)
	}

	cookie := login(t, h)
	rr := do(h, "GET", "/zone?name=evil.example&history=1", "127.0.0.1:1", nil, cookie)
	if rr.Code != http.StatusOK {
		t.Fatalf("history page: %d", rr.Code)
	}
	body := rr.Body.String()

	if !strings.Contains(body, "+ x.evil.example. 60 IN TXT") {
		t.Errorf("added record missing from diff:\n%s", body)
	}
	if !strings.Contains(body, "- x.evil.example. 60 IN A 1.1.1.1") {
		t.Errorf("removed record missing from diff")
	}
	if strings.Contains(body, "IN SOA") {
		t.Errorf("SOA line should be filtered out of the diff")
	}
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Errorf("record rdata was rendered unescaped (XSS)")
	}
}

func TestRecordHandlerGates(t *testing.T) {
	h, _ := newHandler(t, mkConfig(t, ""))
	cookie := login(t, h)

	// missing CSRF -> 400 (the gate before any mutation)
	rr := do(h, "POST", "/zone/record", "127.0.0.1:1",
		map[string]string{"zone": "ddns.myip.gr", "action": "add", "rr": "x.ddns.myip.gr.60INA1.2.3.4"}, cookie)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("missing CSRF should be 400, got %d", rr.Code)
	}

	// valid CSRF but an unparseable record -> a rendered error, no mutation
	csrf := h.csrfFor("admin")
	rr = do(h, "POST", "/zone/record", "127.0.0.1:1",
		map[string]string{"csrf": csrf, "zone": "ddns.myip.gr", "action": "add", "rr": "notarecord"}, cookie)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "parse record") {
		t.Fatalf("bad record should render a parse error: %d\n%s", rr.Code, rr.Body.String())
	}
}

func TestAllowListDenies(t *testing.T) {
	h, _ := newHandler(t, mkConfig(t, `allow = ["127.0.0.0/8"]`))
	if rr := do(h, "GET", "/", "8.8.8.8:1", nil, nil); rr.Code != http.StatusForbidden {
		t.Fatalf("outside allow should be 403: %d", rr.Code)
	}
	if rr := do(h, "GET", "/login", "127.0.0.1:1", nil, nil); rr.Code != http.StatusOK {
		t.Fatalf("inside allow login page: %d", rr.Code)
	}
}

func TestLoginAndDashboard(t *testing.T) {
	h, st := newHandler(t, mkConfig(t, ""))
	if _, _, err := st.Add("home.ddns.myip.gr", "ddns.myip.gr", 60); err != nil {
		t.Fatal(err)
	}

	// no session -> redirect to /login
	if rr := do(h, "GET", "/", "127.0.0.1:1", nil, nil); rr.Code != http.StatusSeeOther {
		t.Fatalf("no session should redirect: %d", rr.Code)
	}
	// wrong password -> 401
	if rr := do(h, "POST", "/login", "127.0.0.1:1", map[string]string{"user": "admin", "pass": "nope"}, nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("bad login: %d", rr.Code)
	}

	cookie := login(t, h)
	rr := do(h, "GET", "/", "127.0.0.1:1", nil, cookie)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "home.ddns.myip.gr") {
		t.Fatalf("dashboard missing record: %d", rr.Code)
	}
}

func TestDDNSCrudWithCSRF(t *testing.T) {
	h, st := newHandler(t, mkConfig(t, ""))
	cookie := login(t, h)
	csrf := h.csrfFor("admin")

	// add without CSRF -> 400
	if rr := do(h, "POST", "/ddns/add", "127.0.0.1:1",
		map[string]string{"fqdn": "a.ddns.myip.gr", "zone": "ddns.myip.gr", "ttl": "60"}, cookie); rr.Code != http.StatusBadRequest {
		t.Fatalf("add without csrf should be 400: %d", rr.Code)
	}
	// add with CSRF -> token shown
	rr := do(h, "POST", "/ddns/add", "127.0.0.1:1",
		map[string]string{"fqdn": "a.ddns.myip.gr", "zone": "ddns.myip.gr", "ttl": "60", "csrf": csrf}, cookie)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "token for") {
		t.Fatalf("add with csrf: %d %s", rr.Code, rr.Body.String())
	}
	if recs, _ := st.List(); len(recs) != 1 || recs[0].FQDN != "a.ddns.myip.gr." {
		t.Fatalf("record not stored: %+v", recs)
	}

	// delete step 1 (CSRF, no confirm) -> confirmation page, NOT deleted yet
	rr = do(h, "POST", "/ddns/del", "127.0.0.1:1",
		map[string]string{"fqdn": "a.ddns.myip.gr", "csrf": csrf}, cookie)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "yes, delete") {
		t.Fatalf("del step1 should confirm: %d", rr.Code)
	}
	if recs, _ := st.List(); len(recs) != 1 {
		t.Fatalf("record deleted before confirm: %+v", recs)
	}
	// delete step 2 (confirm=1) -> redirect, record gone
	rr = do(h, "POST", "/ddns/del", "127.0.0.1:1",
		map[string]string{"fqdn": "a.ddns.myip.gr", "csrf": csrf, "confirm": "1"}, cookie)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("del step2: %d", rr.Code)
	}
	if recs, _ := st.List(); len(recs) != 0 {
		t.Fatalf("record not deleted: %+v", recs)
	}
}

func TestBasicAuthGate(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("gatepass"), bcrypt.MinCost)
	h, _ := newHandler(t, mkConfig(t, `basic_auth = ["gate:`+string(hash)+`"]`))
	// no basic creds -> 401 before even the login page
	if rr := do(h, "GET", "/login", "127.0.0.1:1", nil, nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("basic gate should 401: %d", rr.Code)
	}
	req := httptest.NewRequest("GET", "/login", nil)
	req.RemoteAddr = "127.0.0.1:1"
	req.SetBasicAuth("gate", "gatepass")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("with basic creds login page should load: %d", rr.Code)
	}
}

func TestRotateAndHelp(t *testing.T) {
	h, st := newHandler(t, mkConfig(t, ""))
	_, tok1, _ := st.Add("home.ddns.myip.gr", "ddns.myip.gr", 60)
	cookie := login(t, h)
	csrf := h.csrfFor("admin")

	// help page (read-only) lists the client snippets with a placeholder
	rr := do(h, "GET", "/ddns/help?fqdn=home.ddns.myip.gr", "127.0.0.1:1", nil, cookie)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "MikroTik") || !strings.Contains(rr.Body.String(), "&lt;token&gt;") {
		t.Fatalf("help page: %d", rr.Code)
	}

	// rotate step1 (no confirm) -> confirm page, token unchanged
	rr = do(h, "POST", "/ddns/rotate", "127.0.0.1:1",
		map[string]string{"fqdn": "home.ddns.myip.gr", "csrf": csrf}, cookie)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "yes, rotate") {
		t.Fatalf("rotate confirm: %d", rr.Code)
	}
	if _, err := st.Lookup(tok1); err != nil {
		t.Fatal("token rotated before confirm")
	}
	// rotate step2 -> new token shown, old invalid
	rr = do(h, "POST", "/ddns/rotate", "127.0.0.1:1",
		map[string]string{"fqdn": "home.ddns.myip.gr", "csrf": csrf, "confirm": "1"}, cookie)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "token for") {
		t.Fatalf("rotate result: %d", rr.Code)
	}
	if _, err := st.Lookup(tok1); err == nil {
		t.Fatal("old token still valid after rotate")
	}
	// rotate without CSRF -> 400
	if rr := do(h, "POST", "/ddns/rotate", "127.0.0.1:1",
		map[string]string{"fqdn": "home.ddns.myip.gr", "confirm": "1"}, cookie); rr.Code != http.StatusBadRequest {
		t.Fatalf("rotate without csrf: %d", rr.Code)
	}
}
