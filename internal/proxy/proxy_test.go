package proxy

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
