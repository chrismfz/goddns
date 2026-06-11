package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/chrismfz/goddns/internal/config"
)

func upstream(t *testing.T) (*httptest.Server, *http.Request) {
	t.Helper()
	var got http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = *r
		fmt.Fprintf(w, "hello from upstream, host=%s xff=%s", r.Host, r.Header.Get("X-Forwarded-For"))
	}))
	t.Cleanup(srv.Close)
	return srv, &got
}

func newProxy(t *testing.T, hosts map[string]config.ProxyRule) *Proxy {
	t.Helper()
	cfg := &config.Config{Proxy: hosts}
	p := New()
	if err := p.Update(cfg); err != nil {
		t.Fatal(err)
	}
	return p
}

func request(p *Proxy, host, path, remote string) (int, string) {
	req := httptest.NewRequest("GET", "http://"+host+path, nil)
	req.Host = host
	req.RemoteAddr = remote
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)
	b, _ := io.ReadAll(rr.Result().Body)
	return rr.Code, strings.TrimSpace(string(b))
}

func TestRouteAndForward(t *testing.T) {
	up, _ := upstream(t)
	p := newProxy(t, map[string]config.ProxyRule{
		"orion-idrac.internal.myip.gr": {Upstream: up.URL},
	})

	code, body := request(p, "orion-idrac.internal.myip.gr", "/x", "94.67.31.235:50000")
	if code != 200 || !strings.Contains(body, "hello from upstream") {
		t.Fatalf("forward: %d %q", code, body)
	}
	// Host header rewritten to upstream's by default, XFF carries the client.
	if !strings.Contains(body, "host="+strings.TrimPrefix(up.URL, "http://")) {
		t.Fatalf("upstream host not set: %q", body)
	}
	if !strings.Contains(body, "xff=94.67.31.235") {
		t.Fatalf("xff missing: %q", body)
	}
}

func TestPreserveHost(t *testing.T) {
	up, _ := upstream(t)
	p := newProxy(t, map[string]config.ProxyRule{
		"a.internal.myip.gr": {Upstream: up.URL, PreserveHost: true},
	})
	_, body := request(p, "a.internal.myip.gr", "/", "1.2.3.4:1")
	if !strings.Contains(body, "host=a.internal.myip.gr") {
		t.Fatalf("inbound host not preserved: %q", body)
	}
}

func TestUnknownHost(t *testing.T) {
	p := newProxy(t, map[string]config.ProxyRule{})
	if code, _ := request(p, "nope.internal.myip.gr", "/", "1.2.3.4:1"); code != http.StatusNotFound {
		t.Fatalf("unknown host: %d", code)
	}
}

func TestAllowList(t *testing.T) {
	up, _ := upstream(t)
	p := newProxy(t, map[string]config.ProxyRule{
		"a.internal.myip.gr": {Upstream: up.URL, Allow: []string{"94.67.0.0/16"}},
	})
	if code, _ := request(p, "a.internal.myip.gr", "/", "94.67.31.235:1"); code != 200 {
		t.Fatalf("allowed peer rejected: %d", code)
	}
	if code, _ := request(p, "a.internal.myip.gr", "/", "8.8.8.8:1"); code != http.StatusForbidden {
		t.Fatalf("denied peer passed: %d", code)
	}
}

func TestRateLimit(t *testing.T) {
	up, _ := upstream(t)
	p := newProxy(t, map[string]config.ProxyRule{
		"a.internal.myip.gr": {Upstream: up.URL, RateLimit: 2}, // burst 4
	})
	limited := false
	for i := 0; i < 10; i++ {
		if code, _ := request(p, "a.internal.myip.gr", "/", "1.2.3.4:1"); code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("rate limit never kicked in")
	}
	// A different client IP has its own bucket.
	if code, _ := request(p, "a.internal.myip.gr", "/", "5.6.7.8:1"); code != 200 {
		t.Fatalf("other client affected by limit: %d", code)
	}
}

func TestHotSwapRoutes(t *testing.T) {
	up, _ := upstream(t)
	p := newProxy(t, map[string]config.ProxyRule{
		"a.internal.myip.gr": {Upstream: up.URL},
	})
	if code, _ := request(p, "b.internal.myip.gr", "/", "1.2.3.4:1"); code != http.StatusNotFound {
		t.Fatalf("b should 404 before swap: %d", code)
	}
	if err := p.Update(&config.Config{Proxy: map[string]config.ProxyRule{
		"b.internal.myip.gr": {Upstream: up.URL},
	}}); err != nil {
		t.Fatal(err)
	}
	if code, _ := request(p, "b.internal.myip.gr", "/", "1.2.3.4:1"); code != 200 {
		t.Fatalf("b after swap: %d", code)
	}
	if code, _ := request(p, "a.internal.myip.gr", "/", "1.2.3.4:1"); code != http.StatusNotFound {
		t.Fatalf("a should be gone after swap: %d", code)
	}
}

func TestUpstreamDown(t *testing.T) {
	// Closed port -> 502 from the ErrorHandler.
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := "http://" + l.Addr().String()
	l.Close()
	p := newProxy(t, map[string]config.ProxyRule{
		"a.internal.myip.gr": {Upstream: dead},
	})
	if code, _ := request(p, "a.internal.myip.gr", "/", "1.2.3.4:1"); code != http.StatusBadGateway {
		t.Fatalf("dead upstream: %d", code)
	}
}

func TestIPv6LimiterBucketing(t *testing.T) {
	l := newLimiter(2) // burst 4
	// Same /64, different addresses -> same bucket.
	for i := 0; i < 4; i++ {
		if !l.allow(net.ParseIP(fmt.Sprintf("2001:db8:1:1::%d", i+1))) {
			t.Fatalf("burst request %d denied early", i)
		}
	}
	if l.allow(net.ParseIP("2001:db8:1:1::ffff")) {
		t.Fatal("rotating within the /64 escaped the bucket")
	}
	// Different /64 -> fresh bucket.
	if !l.allow(net.ParseIP("2001:db8:2:2::1")) {
		t.Fatal("distinct /64 wrongly limited")
	}
	// nil peer shares one bucket instead of bypassing.
	for i := 0; i < 4; i++ {
		l.allow(nil)
	}
	if l.allow(nil) {
		t.Fatal("nil peer bypassed the limiter")
	}
}

func TestTrailingDotHost(t *testing.T) {
	up, _ := upstream(t)
	p := newProxy(t, map[string]config.ProxyRule{
		"a.internal.myip.gr": {Upstream: up.URL},
	})
	if code, _ := request(p, "A.internal.myip.gr.", "/", "1.2.3.4:1"); code != 200 {
		t.Fatalf("trailing-dot host not matched: %d", code)
	}
}

func TestXRealIPNotSpoofable(t *testing.T) {
	up, got := upstream(t)
	p := newProxy(t, map[string]config.ProxyRule{
		"a.internal.myip.gr": {Upstream: up.URL},
	})
	req := httptest.NewRequest("GET", "http://a.internal.myip.gr/", nil)
	req.Host = "a.internal.myip.gr"
	req.RemoteAddr = "94.67.31.235:50000"
	req.Header.Set("X-Real-IP", "10.0.0.1") // attacker-supplied
	req.Header.Set("True-Client-IP", "10.0.0.1")
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)
	if got.Header.Get("X-Real-IP") != "94.67.31.235" {
		t.Fatalf("X-Real-IP reaching upstream: %q", got.Header.Get("X-Real-IP"))
	}
	if got.Header.Get("True-Client-IP") != "" {
		t.Fatalf("True-Client-IP passed through: %q", got.Header.Get("True-Client-IP"))
	}
}

func TestBasicAuth(t *testing.T) {
	// bcrypt("s3cretpass", cost 10)
	hash, err := bcrypt.GenerateFromPassword([]byte("s3cretpass"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	up, got := upstream(t)
	p := newProxy(t, map[string]config.ProxyRule{
		"a.internal.myip.gr": {
			Upstream:  up.URL,
			BasicAuth: []string{"chris:" + string(hash)},
		},
	})

	do := func(setAuth func(*http.Request)) int {
		req := httptest.NewRequest("GET", "http://a.internal.myip.gr/", nil)
		req.Host = "a.internal.myip.gr"
		req.RemoteAddr = "1.2.3.4:1"
		if setAuth != nil {
			setAuth(req)
		}
		rr := httptest.NewRecorder()
		p.ServeHTTP(rr, req)
		return rr.Code
	}

	// no creds -> 401 with challenge
	req := httptest.NewRequest("GET", "http://a.internal.myip.gr/", nil)
	req.Host = "a.internal.myip.gr"
	req.RemoteAddr = "1.2.3.4:1"
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized || rr.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("no creds: %d %q", rr.Code, rr.Header().Get("WWW-Authenticate"))
	}
	// wrong password / unknown user -> 401
	if code := do(func(r *http.Request) { r.SetBasicAuth("chris", "wrong") }); code != http.StatusUnauthorized {
		t.Fatalf("wrong pass: %d", code)
	}
	if code := do(func(r *http.Request) { r.SetBasicAuth("nobody", "s3cretpass") }); code != http.StatusUnauthorized {
		t.Fatalf("unknown user: %d", code)
	}
	// correct creds -> 200, and Authorization does NOT reach the upstream
	if code := do(func(r *http.Request) { r.SetBasicAuth("chris", "s3cretpass") }); code != 200 {
		t.Fatalf("good creds: %d", code)
	}
	if got.Header.Get("Authorization") != "" {
		t.Fatalf("Authorization leaked upstream: %q", got.Header.Get("Authorization"))
	}
}

func TestAuthAndAllowBothEnforced(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("s3cretpass"), bcrypt.MinCost)
	up, _ := upstream(t)
	p := newProxy(t, map[string]config.ProxyRule{
		"a.internal.myip.gr": {
			Upstream:  up.URL,
			Allow:     []string{"94.67.0.0/16"},
			BasicAuth: []string{"chris:" + string(hash)},
		},
	})
	req := httptest.NewRequest("GET", "http://a.internal.myip.gr/", nil)
	req.Host = "a.internal.myip.gr"
	req.RemoteAddr = "8.8.8.8:1" // outside allow
	req.SetBasicAuth("chris", "s3cretpass")
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("good creds must not bypass the allow list: %d", rr.Code)
	}
}
