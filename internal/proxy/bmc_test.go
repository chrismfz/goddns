package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/chrismfz/goddns/internal/config"
)

func TestBMCCompatRewritesOriginHostReferer(t *testing.T) {
	var got http.Request
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = *r
		w.WriteHeader(200)
	}))
	t.Cleanup(up.Close)
	upHost := strings.TrimPrefix(up.URL, "http://")

	p := newProxy(t, map[string]config.ProxyRule{
		"idrac.internal.myip.gr": {Upstream: up.URL, BMCCompat: true},
	})
	req := httptest.NewRequest("GET", "http://idrac.internal.myip.gr/console", nil)
	req.Host = "idrac.internal.myip.gr"
	req.Header.Set("Origin", "https://idrac.internal.myip.gr")
	req.Header.Set("Referer", "https://idrac.internal.myip.gr/restgui/index.html")
	req.RemoteAddr = "1.2.3.4:5000"
	p.ServeHTTP(httptest.NewRecorder(), req)

	// Host forced to the upstream (the BMC 400s an unknown Host).
	if got.Host != upHost {
		t.Fatalf("Host = %q, want upstream %q", got.Host, upHost)
	}
	// Origin rewritten to the upstream origin so the console's same-origin check passes.
	if o := got.Header.Get("Origin"); o != "http://"+upHost {
		t.Fatalf("Origin = %q, want http://%s", o, upHost)
	}
	// Referer host rewritten, path preserved.
	if r := got.Header.Get("Referer"); r != "http://"+upHost+"/restgui/index.html" {
		t.Fatalf("Referer = %q", r)
	}
}

func TestBMCCompatForcesHostOverPreserve(t *testing.T) {
	var got http.Request
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = *r
		w.WriteHeader(200)
	}))
	t.Cleanup(up.Close)
	upHost := strings.TrimPrefix(up.URL, "http://")

	// preserve_host AND bmc_compat both set: bmc wins (Host must be the upstream).
	p := newProxy(t, map[string]config.ProxyRule{
		"idrac.internal.myip.gr": {Upstream: up.URL, BMCCompat: true, PreserveHost: true},
	})
	req := httptest.NewRequest("GET", "http://idrac.internal.myip.gr/", nil)
	req.Host = "idrac.internal.myip.gr"
	req.RemoteAddr = "1.2.3.4:5000"
	p.ServeHTTP(httptest.NewRecorder(), req)

	if got.Host != upHost {
		t.Fatalf("bmc_compat must force Host=upstream even with preserve_host; got %q", got.Host)
	}
}

func TestBMCCompatRewritesRedirectBack(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// the BMC emits an absolute redirect to its own address (the Host it saw)
		w.Header().Set("Location", "https://"+r.Host+"/login.html")
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(up.Close)

	p := newProxy(t, map[string]config.ProxyRule{
		"idrac.internal.myip.gr": {Upstream: up.URL, BMCCompat: true},
	})
	req := httptest.NewRequest("GET", "http://idrac.internal.myip.gr/", nil)
	req.Host = "idrac.internal.myip.gr"
	req.RemoteAddr = "1.2.3.4:5000"
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	if loc := rr.Result().Header.Get("Location"); loc != "https://idrac.internal.myip.gr/login.html" {
		t.Fatalf("self-referential redirect not rewritten back to the vhost: %q", loc)
	}
}

func TestBMCCompatOffLeavesHeadersAlone(t *testing.T) {
	var got http.Request
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = *r
		w.Header().Set("Location", "https://"+r.Host+"/x")
		w.WriteHeader(http.StatusFound)
	}))
	t.Cleanup(up.Close)
	upHost := strings.TrimPrefix(up.URL, "http://")

	p := newProxy(t, map[string]config.ProxyRule{"app.myip.gr": {Upstream: up.URL}}) // bmc off
	req := httptest.NewRequest("GET", "http://app.myip.gr/", nil)
	req.Host = "app.myip.gr"
	req.Header.Set("Origin", "https://app.myip.gr")
	req.RemoteAddr = "1.2.3.4:5000"
	rr := httptest.NewRecorder()
	p.ServeHTTP(rr, req)

	// A normal app keeps the real Origin and an un-rewritten Location.
	if o := got.Header.Get("Origin"); o != "https://app.myip.gr" {
		t.Fatalf("Origin should be untouched without bmc_compat: %q", o)
	}
	if loc := rr.Result().Header.Get("Location"); !strings.Contains(loc, upHost) {
		t.Fatalf("Location should be untouched without bmc_compat: %q", loc)
	}
}
