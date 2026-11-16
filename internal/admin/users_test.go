package admin

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/named"
	"github.com/chrismfz/goddns/internal/service"
)

func loginAs(t *testing.T, h *Handler, user, pass string) *http.Cookie {
	t.Helper()
	rr := do(h, "POST", "/login", "127.0.0.1:1", map[string]string{"user": user, "pass": url.QueryEscape(pass)}, nil)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("login %s: %d", user, rr.Code)
	}
	for _, c := range rr.Result().Cookies() {
		if c.Name == cookieName {
			return c
		}
	}
	t.Fatal("no session cookie")
	return nil
}

func TestUsersPageAndUserRole(t *testing.T) {
	h, _ := newHandler(t, mkConfig(t, ""))
	admin := login(t, h)
	csrf := h.csrfFor("admin")

	// add a user-role login through the page
	rr := do(h, "POST", "/users", "127.0.0.1:1", map[string]string{
		"csrf": csrf, "op": "add", "name": "alice", "pass": "alicepass1", "role": "user"}, admin)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("add user: %d %s", rr.Code, rr.Body.String())
	}
	if rr := do(h, "GET", "/users", "127.0.0.1:1", nil, admin); !strings.Contains(rr.Body.String(), "alice") {
		t.Fatal("users page does not list alice")
	}
	// no CSRF -> 400
	if rr := do(h, "POST", "/users", "127.0.0.1:1", map[string]string{"op": "del", "name": "alice", "confirm": "1"}, admin); rr.Code != http.StatusBadRequest {
		t.Fatalf("users POST without csrf: %d", rr.Code)
	}

	alice := loginAs(t, h, "alice", "alicepass1")
	if rr := do(h, "GET", "/", "127.0.0.1:1", nil, alice); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "No zones are assigned") {
		t.Fatalf("user home: %d", rr.Code)
	}
	// every admin page is 403 for the user role, GET and POST alike
	for _, p := range []string{"/zone?name=x", "/zone?name=x&history=1", "/logs?which=access", "/traffic", "/users", "/passwd",
		"/ddns/help?fqdn=x", "/proxy/edit?host=x"} {
		if rr := do(h, "GET", p, "127.0.0.1:1", nil, alice); rr.Code != http.StatusForbidden {
			t.Errorf("GET %s as user: %d", p, rr.Code)
		}
	}
	aliceCSRF := h.csrfFor("alice")
	for _, p := range []string{"/ddns/add", "/ddns/del", "/zone/record", "/zone/restore", "/proxy/set", "/proxy/del", "/users"} {
		if rr := do(h, "POST", p, "127.0.0.1:1", map[string]string{"csrf": aliceCSRF, "op": "add", "name": "eve",
			"pass": "evepass123", "role": "admin", "fqdn": "a.b", "zone": "b", "confirm": "1", "id": "1", "action": "add", "rr": "a.b 60 IN A 1.1.1.1"}, alice); rr.Code != http.StatusForbidden {
			t.Errorf("POST %s as user: %d", p, rr.Code)
		}
	}
	if _, _, ok := h.svc.Lookup("eve"); ok {
		t.Fatal("a user-role login created an account")
	}

	// changing alice's role ends her session
	if rr := do(h, "POST", "/users", "127.0.0.1:1", map[string]string{"csrf": csrf, "op": "role", "name": "alice", "role": "admin"}, admin); rr.Code != http.StatusSeeOther {
		t.Fatalf("set role: %d", rr.Code)
	}
	if rr := do(h, "GET", "/", "127.0.0.1:1", nil, alice); rr.Code != http.StatusSeeOther {
		t.Fatalf("old session survived a role change: %d", rr.Code)
	}
	// disabling ends it and blocks login
	do(h, "POST", "/users", "127.0.0.1:1", map[string]string{"csrf": csrf, "op": "disable", "name": "alice"}, admin)
	if rr := do(h, "POST", "/login", "127.0.0.1:2", map[string]string{"user": "alice", "pass": "alicepass1"}, nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("disabled login: %d", rr.Code)
	}
	// a goddns.conf admin can't be edited from the page
	rr = do(h, "POST", "/users", "127.0.0.1:1", map[string]string{"csrf": csrf, "op": "role", "name": "admin", "role": "user"}, admin)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "goddns.conf") {
		t.Fatalf("editing a conf admin: %d", rr.Code)
	}
	// delete is two-phase
	rr = do(h, "POST", "/users", "127.0.0.1:1", map[string]string{"csrf": csrf, "op": "del", "name": "alice"}, admin)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "yes, delete") {
		t.Fatalf("delete preview: %d", rr.Code)
	}
	if _, _, ok := h.svc.Lookup("alice"); !ok {
		// disabled users don't resolve; check the list instead
		if rr := do(h, "GET", "/users", "127.0.0.1:1", nil, admin); !strings.Contains(rr.Body.String(), "alice") {
			t.Fatal("preview deleted the user")
		}
	}
	do(h, "POST", "/users", "127.0.0.1:1", map[string]string{"csrf": csrf, "op": "del", "name": "alice", "confirm": "1"}, admin)
	if rr := do(h, "GET", "/users", "127.0.0.1:1", nil, admin); strings.Contains(rr.Body.String(), "<b>alice</b>") {
		t.Fatal("alice still listed after delete")
	}
}

func TestAccountPasswordChangeKeepsSession(t *testing.T) {
	h, _ := newHandler(t, mkConfig(t, ""))
	admin := login(t, h)
	do(h, "POST", "/users", "127.0.0.1:1", map[string]string{"csrf": h.csrfFor("admin"), "op": "add", "name": "bob", "pass": "bobpass123", "role": "user"}, admin)
	bob := loginAs(t, h, "bob", "bobpass123")
	csrf := h.csrfFor("bob")
	rr := do(h, "POST", "/account", "127.0.0.1:1", map[string]string{"csrf": csrf, "current": "bobpass123", "new": "newpass123", "repeat": "nope"}, bob)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("mismatched repeat: %d", rr.Code)
	}
	rr = do(h, "POST", "/account", "127.0.0.1:1", map[string]string{"csrf": csrf, "current": "bobpass123", "new": "newpass123", "repeat": "newpass123"}, bob)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "Password changed") {
		t.Fatalf("change: %d %s", rr.Code, rr.Body.String())
	}
	var fresh *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == cookieName {
			fresh = c
		}
	}
	if fresh == nil {
		t.Fatal("no re-issued session cookie")
	}
	if rr := do(h, "GET", "/", "127.0.0.1:1", nil, bob); rr.Code != http.StatusSeeOther {
		t.Fatal("the pre-change session still works")
	}
	if rr := do(h, "GET", "/", "127.0.0.1:1", nil, fresh); rr.Code != http.StatusOK {
		t.Fatalf("re-issued session: %d", rr.Code)
	}
	loginAs(t, h, "bob", "newpass123")
}

// The current-password check is throttled per account, and error pages keep
// the security headers (they must be set before WriteHeader).
func TestAccountThrottleAndErrorHeaders(t *testing.T) {
	h, _ := newHandler(t, mkConfig(t, ""))
	admin := login(t, h)
	do(h, "POST", "/users", "127.0.0.1:1", map[string]string{"csrf": h.csrfFor("admin"), "op": "add", "name": "bob", "pass": "bobpass123", "role": "user"}, admin)
	bob := loginAs(t, h, "bob", "bobpass123")
	csrf := h.csrfFor("bob")
	var last *httptest.ResponseRecorder
	for i := 0; i < 20; i++ {
		last = do(h, "POST", "/account", "127.0.0.1:1", map[string]string{"csrf": csrf, "current": "guess" + strconv.Itoa(i) + "xx", "new": "newpass123", "repeat": "newpass123"}, bob)
		if last.Code == http.StatusTooManyRequests {
			break
		}
		if last.Code != http.StatusBadRequest {
			t.Fatalf("wrong current password: %d", last.Code)
		}
		if csp := last.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
			t.Fatalf("error page lost its CSP: %q", csp)
		}
	}
	if last.Code != http.StatusTooManyRequests {
		t.Fatal("guessing the current password was never throttled")
	}
	// the right password is refused too while throttled
	if rr := do(h, "POST", "/account", "127.0.0.1:9", map[string]string{"csrf": csrf, "current": "bobpass123", "new": "newpass123", "repeat": "newpass123"}, bob); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("per-account throttle didn't hold from another IP: %d", rr.Code)
	}
	if rr := do(h, "POST", "/login", "192.0.2.50:7", map[string]string{"user": "nobody", "pass": "whatever1"}, nil); rr.Code != http.StatusUnauthorized ||
		!strings.Contains(rr.Header().Get("Content-Security-Policy"), "default-src 'none'") {
		t.Fatalf("failed-login page: %d csp=%q", rr.Code, rr.Header().Get("Content-Security-Policy"))
	}
}

func TestOwnResetOnUsersPageKeepsSession(t *testing.T) {
	h, _ := newHandler(t, mkConfig(t, ""))
	admin := login(t, h)
	do(h, "POST", "/users", "127.0.0.1:1", map[string]string{"csrf": h.csrfFor("admin"), "op": "add", "name": "carol", "pass": "carolpass1", "role": "admin"}, admin)
	carol := loginAs(t, h, "carol", "carolpass1")
	rr := do(h, "POST", "/users", "127.0.0.1:1", map[string]string{"csrf": h.csrfFor("carol"), "op": "passwd", "name": "carol", "pass": "carolpass2"}, carol)
	var fresh *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == cookieName {
			fresh = c
		}
	}
	if rr.Code != http.StatusSeeOther || fresh == nil {
		t.Fatalf("own reset: %d cookie=%v", rr.Code, fresh)
	}
	if rr := do(h, "GET", "/users", "127.0.0.1:1", nil, fresh); rr.Code != http.StatusOK {
		t.Fatalf("re-issued session after own reset: %d", rr.Code)
	}
}

func TestGrantedUserUI(t *testing.T) {
	h, _ := newHandler(t, mkConfig(t, ""))
	inv := &named.Inventory{Zones: []named.Zone{
		{Name: "example.com", Type: "master", Path: "/var/named/example.com.db", Dynamic: true},
		{Name: "other.net", Type: "master", Path: "/var/named/other.net.db", Dynamic: true},
	}, Keys: []named.Key{{Name: "goddns-key", Algorithm: "hmac-sha256"}}}
	h.svc.Inv = func(*config.Config) (*named.Inventory, error) { return inv, nil }
	admin := login(t, h)
	csrf := h.csrfFor("admin")
	do(h, "POST", "/users", "127.0.0.1:1", map[string]string{"csrf": csrf, "op": "add", "name": "alice", "pass": "alicepass1", "role": "user"}, admin)
	if rr := do(h, "POST", "/users", "127.0.0.1:1", map[string]string{"csrf": csrf, "op": "grant", "name": "alice", "zone": "example.com"}, admin); rr.Code != http.StatusSeeOther {
		t.Fatalf("grant: %d %s", rr.Code, rr.Body.String())
	}
	if rr := do(h, "POST", "/users", "127.0.0.1:1", map[string]string{"csrf": csrf, "op": "grant", "name": "alice", "zone": "typo.example"}, admin); rr.Code != http.StatusBadRequest {
		t.Fatalf("grant of an unserved zone: %d", rr.Code)
	}
	if rr := do(h, "GET", "/users", "127.0.0.1:1", nil, admin); !strings.Contains(rr.Body.String(), `name="zone" value="example.com"`) {
		t.Fatal("users page doesn't show the grant with its revoke form")
	}

	alice := loginAs(t, h, "alice", "alicepass1")
	home := do(h, "GET", "/", "127.0.0.1:1", nil, alice).Body.String()
	if !strings.Contains(home, `/zone?name=example.com`) || strings.Contains(home, "other.net") {
		t.Fatal("home doesn't list exactly the granted zone")
	}
	zones := do(h, "GET", "/zones", "127.0.0.1:1", nil, alice)
	body := zones.Body.String()
	if zones.Code != http.StatusOK || !strings.Contains(body, "example.com") || strings.Contains(body, "other.net") ||
		strings.Contains(body, "goddns-key") || strings.Contains(body, "/var/named") {
		t.Fatalf("zones page leaks beyond the grant (%d):\n%s", zones.Code, body)
	}
	if rr := do(h, "GET", "/zone?name=other.net", "127.0.0.1:1", nil, alice); rr.Code != http.StatusForbidden {
		t.Fatalf("ungranted zone view: %d", rr.Code)
	}
	if rr := do(h, "GET", "/zone?name=example.com", "127.0.0.1:1", nil, alice); rr.Code == http.StatusForbidden {
		t.Fatal("granted zone view refused")
	}
	ac := h.csrfFor("alice")
	if rr := do(h, "POST", "/ddns/add", "127.0.0.1:1", map[string]string{"csrf": ac, "fqdn": "cam.other.net", "zone": "other.net"}, alice); rr.Code != http.StatusForbidden {
		t.Fatalf("DDNS add in an ungranted zone: %d", rr.Code)
	}
	if rr := do(h, "POST", "/ddns/add", "127.0.0.1:1", map[string]string{"csrf": ac, "fqdn": "cam.example.com", "zone": "example.com"}, alice); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "cam.example.com") {
		t.Fatalf("DDNS add in the granted zone: %d", rr.Code)
	}
	if home := do(h, "GET", "/", "127.0.0.1:1", nil, alice).Body.String(); !strings.Contains(home, "cam.example.com") {
		t.Fatal("home doesn't list the user's DDNS record")
	}
	// revoking ends access at once (no session change needed)
	do(h, "POST", "/users", "127.0.0.1:1", map[string]string{"csrf": csrf, "op": "revoke", "name": "alice", "zone": "example.com"}, admin)
	if rr := do(h, "GET", "/zone?name=example.com", "127.0.0.1:1", nil, alice); rr.Code != http.StatusForbidden {
		t.Fatalf("after revoke: %d", rr.Code)
	}
}

func TestAccountAPITokens(t *testing.T) {
	h, _ := newHandler(t, mkConfig(t, ""))
	admin := login(t, h)
	do(h, "POST", "/users", "127.0.0.1:1", map[string]string{"csrf": h.csrfFor("admin"), "op": "add", "name": "fay", "pass": "faypass123", "role": "user"}, admin)
	fay := loginAs(t, h, "fay", "faypass123")
	csrf := h.csrfFor("fay")
	page := do(h, "GET", "/account", "127.0.0.1:1", nil, fay).Body.String()
	if !strings.Contains(page, `value="ddns:write"`) || strings.Contains(page, `value="users:admin"`) {
		t.Fatal("account page offers scopes beyond the user role")
	}
	rr := do(h, "POST", "/account/apitoken", "127.0.0.1:1", map[string]string{"csrf": csrf, "op": "add", "name": "ci", "scope": "zones:read", "expires": "30"}, fay)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "gdapi_") {
		t.Fatalf("create: %d", rr.Code)
	}
	if again := do(h, "GET", "/account", "127.0.0.1:1", nil, fay).Body.String(); strings.Contains(again, "gdapi_") {
		t.Fatal("the token was shown a second time")
	}
	rr = do(h, "POST", "/account/apitoken", "127.0.0.1:1", map[string]string{"csrf": csrf, "op": "add", "name": "x", "scope": "users:admin"}, fay)
	if rr.Code != 400 {
		t.Fatalf("admin scope for a user: %d", rr.Code)
	}
	toks, _ := h.svc.APITokens(service.Actor{User: "fay", Role: service.RoleUser}, "fay")
	if len(toks) != 1 {
		t.Fatalf("tokens: %+v", toks)
	}
	if rr := do(h, "POST", "/account/apitoken", "127.0.0.1:1", map[string]string{"op": "revoke", "id": fmt.Sprint(toks[0].ID)}, fay); rr.Code != 400 {
		t.Fatalf("revoke without csrf: %d", rr.Code)
	}
	if rr := do(h, "POST", "/account/apitoken", "127.0.0.1:1", map[string]string{"csrf": csrf, "op": "revoke", "id": fmt.Sprint(toks[0].ID)}, fay); rr.Code != http.StatusSeeOther {
		t.Fatalf("revoke: %d", rr.Code)
	}
}
