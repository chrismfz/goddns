package proxy

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/chrismfz/goddns/internal/config"
)

func stat(p *Proxy, host string) (HostStat, bool) {
	for _, s := range p.Stats() {
		if s.Host == host {
			return s, true
		}
	}
	return HostStat{}, false
}

func TestStatsCountRequestAndBytes(t *testing.T) {
	up, _ := upstream(t)
	p := newProxy(t, map[string]config.ProxyRule{"a.myip.gr": {Upstream: up.URL}})

	code, body := request(p, "a.myip.gr", "/x", "1.2.3.4:5000")
	if code != 200 {
		t.Fatalf("code = %d", code)
	}
	s, ok := stat(p, "a.myip.gr")
	if !ok {
		t.Fatal("no stat entry for the host")
	}
	if s.Requests != 1 {
		t.Fatalf("requests = %d, want 1", s.Requests)
	}
	if s.Active != 0 {
		t.Fatalf("active = %d, want 0 after the request finished", s.Active)
	}
	if s.Status2xx != 1 || s.Status4xx != 0 || s.Status5xx != 0 {
		t.Fatalf("status buckets wrong: %+v", s)
	}
	if int(s.BytesOut) < len(body) || s.BytesOut == 0 {
		t.Fatalf("bytesOut = %d, want >= response body (%d)", s.BytesOut, len(body))
	}
	if s.LastSeen.IsZero() {
		t.Fatal("last seen not stamped")
	}
}

func TestStatsBytesIn(t *testing.T) {
	up, _ := upstream(t)
	p := newProxy(t, map[string]config.ProxyRule{"a.myip.gr": {Upstream: up.URL}})

	payload := "the request body the client uploaded"
	req := httptest.NewRequest("POST", "http://a.myip.gr/up", strings.NewReader(payload))
	req.Host = "a.myip.gr"
	req.RemoteAddr = "1.2.3.4:5000"
	p.ServeHTTP(httptest.NewRecorder(), req)

	s, _ := stat(p, "a.myip.gr")
	if int(s.BytesIn) < len(payload) {
		t.Fatalf("bytesIn = %d, want >= uploaded body (%d)", s.BytesIn, len(payload))
	}
}

func TestStatsSeedsConfiguredHosts(t *testing.T) {
	// configured hosts appear in the snapshot immediately (at zero), before any
	// request, so the dashboard lists them instead of looking empty.
	p := newProxy(t, map[string]config.ProxyRule{
		"a.myip.gr": {Upstream: "http://127.0.0.1:1"},
		"b.myip.gr": {Upstream: "http://127.0.0.1:1"},
	})
	if n := len(p.Stats()); n != 2 {
		t.Fatalf("configured hosts not seeded: %d entries, want 2", n)
	}
	s, ok := stat(p, "a.myip.gr")
	if !ok || s.Requests != 0 || !s.LastSeen.IsZero() {
		t.Fatalf("seeded host should start at zero/never: ok=%v %+v", ok, s)
	}
}

func TestStatsUnknownHostNoEntry(t *testing.T) {
	p := newProxy(t, map[string]config.ProxyRule{"a.myip.gr": {Upstream: "http://127.0.0.1:1"}})
	before := len(p.Stats()) // the seeded configured host(s)
	// a flood of random Host headers (the 404 path) must NOT create counters,
	// or the map would grow without bound on the public listener.
	for _, h := range []string{"evil1.example", "evil2.example", "random-scan.example"} {
		if code, _ := request(p, h, "/", "9.9.9.9:1"); code != http.StatusNotFound {
			t.Fatalf("unknown host %s: code %d, want 404", h, code)
		}
	}
	if n := len(p.Stats()); n != before {
		t.Fatalf("unknown hosts created %d new stat entries, want 0", n-before)
	}
	for _, s := range p.Stats() {
		if s.Host != "a.myip.gr" {
			t.Fatalf("an unknown host leaked into stats: %q", s.Host)
		}
	}
}

func TestStatsCountsBlockedTraffic(t *testing.T) {
	// an allow list that rejects the client: the request is 403'd but still
	// counted, so attack/blocked traffic is visible on the dashboard.
	p := newProxy(t, map[string]config.ProxyRule{
		"a.myip.gr": {Upstream: "http://127.0.0.1:1", Allow: []string{"10.0.0.0/8"}},
	})
	if code, _ := request(p, "a.myip.gr", "/", "1.2.3.4:5000"); code != http.StatusForbidden {
		t.Fatalf("want 403 for a blocked client")
	}
	s, ok := stat(p, "a.myip.gr")
	if !ok || s.Requests != 1 || s.Status4xx != 1 {
		t.Fatalf("blocked request not counted: ok=%v %+v", ok, s)
	}
}

func TestStatsPrunedOnReload(t *testing.T) {
	up, _ := upstream(t)
	p := newProxy(t, map[string]config.ProxyRule{
		"a.myip.gr": {Upstream: up.URL},
		"b.myip.gr": {Upstream: up.URL},
	})
	request(p, "a.myip.gr", "/", "1.2.3.4:1")
	request(p, "b.myip.gr", "/", "1.2.3.4:1")
	if len(p.Stats()) != 2 {
		t.Fatalf("want 2 stat entries, got %d", len(p.Stats()))
	}
	// a reload drops host b -> its counters are pruned
	if err := p.Update(&config.Config{Proxy: map[string]config.ProxyRule{"a.myip.gr": {Upstream: up.URL}}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := stat(p, "b.myip.gr"); ok {
		t.Fatal("removed host b should have been pruned from stats")
	}
	if _, ok := stat(p, "a.myip.gr"); !ok {
		t.Fatal("kept host a should still have stats")
	}
}

// fakeConn satisfies net.Conn for the byte-wrapper tests; only Read/Write are
// exercised (the embedded nil Conn would panic on the rest, which we never call).
type fakeConn struct {
	net.Conn
	r *bytes.Reader
	w *bytes.Buffer
}

func (f *fakeConn) Read(b []byte) (int, error)  { return f.r.Read(b) }
func (f *fakeConn) Write(b []byte) (int, error) { return f.w.Write(b) }

func TestCountConn(t *testing.T) {
	var in, out atomic.Int64
	fc := &fakeConn{r: bytes.NewReader([]byte("0123456789")), w: &bytes.Buffer{}}
	cc := &countConn{Conn: fc, in: &in, out: &out}

	buf := make([]byte, 4)
	if n, _ := cc.Read(buf); n != 4 {
		t.Fatalf("read %d", n)
	}
	if n, _ := cc.Read(buf); n != 4 {
		t.Fatalf("read %d", n)
	}
	if n, _ := cc.Write([]byte("abc")); n != 3 {
		t.Fatalf("write %d", n)
	}
	if in.Load() != 8 {
		t.Fatalf("in = %d, want 8", in.Load())
	}
	if out.Load() != 3 {
		t.Fatalf("out = %d, want 3", out.Load())
	}
}

func TestCountReadCloser(t *testing.T) {
	var n atomic.Int64
	cr := &countReadCloser{rc: io.NopCloser(strings.NewReader("hello world")), n: &n}
	io.ReadAll(cr)
	if err := cr.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if n.Load() != 11 {
		t.Fatalf("counted %d bytes, want 11", n.Load())
	}
}
