package server

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/ddns"
	"github.com/chrismfz/goddns/internal/store"
)

type fakeBackend struct {
	mu    sync.Mutex
	calls []string
	fail  bool
}

func (f *fakeBackend) Update(fqdn, zone string, ip net.IP, ttl uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return fmt.Errorf("boom")
	}
	f.calls = append(f.calls, fmt.Sprintf("%s %s %s %d", fqdn, zone, ip, ttl))
	return nil
}

func newTestServer(t *testing.T, conf string) (*Server, *store.Store, *fakeBackend) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "goddns.conf")
	if err := os.WriteFile(p, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	fb := &fakeBackend{}
	return &Server{
		Cfg:     func() *config.Config { return cfg },
		Backend: func() ddns.Backend { return fb },
		Store:   st,
	}, st, fb
}

const baseConf = `
cert_file = "/tmp/c.pem"
key_file  = "/tmp/k.pem"
`

func get(t *testing.T, h http.Handler, url string, hdr map[string]string, remote string) (int, string) {
	t.Helper()
	req := httptest.NewRequest("GET", url, nil)
	if remote != "" {
		req.RemoteAddr = remote
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	b, _ := io.ReadAll(rr.Result().Body)
	return rr.Code, strings.TrimSpace(string(b))
}

func TestSimpleUpdateFlow(t *testing.T) {
	s, st, fb := newTestServer(t, baseConf)
	_, tok, err := st.Add("home.myip.gr", "myip.gr", 60)
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()

	// IP from connection peer
	code, body := get(t, h, "/update/"+tok, nil, "2.85.101.222:55555")
	if code != 200 || body != "good 2.85.101.222" {
		t.Fatalf("first update: %d %q", code, body)
	}
	// same IP again -> nochg, no backend call
	code, body = get(t, h, "/update/"+tok, nil, "2.85.101.222:55555")
	if code != 200 || body != "nochg 2.85.101.222" {
		t.Fatalf("nochg: %d %q", code, body)
	}
	if len(fb.calls) != 1 {
		t.Fatalf("backend calls: %v", fb.calls)
	}

	// explicit override via query
	code, body = get(t, h, "/update/"+tok+"?ip=203.0.113.7", nil, "2.85.101.222:55555")
	if code != 200 || body != "good 203.0.113.7" {
		t.Fatalf("override: %d %q", code, body)
	}
	// path-style override
	code, body = get(t, h, "/update/"+tok+"/203.0.113.8", nil, "2.85.101.222:55555")
	if code != 200 || body != "good 203.0.113.8" {
		t.Fatalf("path override: %d %q", code, body)
	}

	// bad token
	code, body = get(t, h, "/update/not-a-token", nil, "2.85.101.222:55555")
	if code != http.StatusForbidden || body != "badauth" {
		t.Fatalf("badauth: %d %q", code, body)
	}
}

func TestBackendErrorIsDNSErr(t *testing.T) {
	s, st, fb := newTestServer(t, baseConf)
	fb.fail = true
	_, tok, _ := st.Add("home.myip.gr", "myip.gr", 60)
	code, body := get(t, s.Handler(), "/update/"+tok, nil, "2.85.101.222:1")
	if code != http.StatusBadGateway || body != "dnserr" {
		t.Fatalf("dnserr: %d %q", code, body)
	}
}

func TestXFFIgnoredFromUntrustedPeer(t *testing.T) {
	// The exact cpsrvd bug class this project replaces: XFF must be ignored
	// unless the peer is an explicitly configured trusted proxy.
	s, st, _ := newTestServer(t, baseConf)
	_, tok, _ := st.Add("home.myip.gr", "myip.gr", 60)
	code, body := get(t, s.Handler(), "/update/"+tok,
		map[string]string{"X-Forwarded-For": "9.9.9.9"}, "2.85.101.222:1")
	if code != 200 || body != "good 2.85.101.222" {
		t.Fatalf("untrusted XFF honoured: %d %q", code, body)
	}
}

func TestXFFHonouredFromTrustedProxy(t *testing.T) {
	s, st, _ := newTestServer(t, baseConf+`trusted_proxies = ["127.0.0.1/32"]`)
	_, tok, _ := st.Add("home.myip.gr", "myip.gr", 60)
	code, body := get(t, s.Handler(), "/update/"+tok,
		map[string]string{"X-Forwarded-For": "2.85.101.222, 127.0.0.1"}, "127.0.0.1:1")
	if code != 200 || body != "good 2.85.101.222" {
		t.Fatalf("trusted XFF: %d %q", code, body)
	}
}

func TestDynDNS2(t *testing.T) {
	s, st, _ := newTestServer(t, baseConf)
	_, tok, _ := st.Add("home.myip.gr", "myip.gr", 60)
	h := s.Handler()

	// token as query param + explicit myip
	code, body := get(t, h, "/nic/update?token="+tok+"&hostname=home.myip.gr&myip=203.0.113.9", nil, "1.2.3.4:1")
	if code != 200 || body != "good 203.0.113.9" {
		t.Fatalf("dyndns2: %d %q", code, body)
	}
	// wrong hostname for this token
	code, body = get(t, h, "/nic/update?token="+tok+"&hostname=other.myip.gr", nil, "1.2.3.4:1")
	if body != "nohost" {
		t.Fatalf("nohost: %d %q", code, body)
	}
	// basic auth password carries the token
	req := httptest.NewRequest("GET", "/nic/update?hostname=home.myip.gr&myip=203.0.113.11", nil)
	req.RemoteAddr = "1.2.3.4:1"
	req.SetBasicAuth("ignored", tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	b, _ := io.ReadAll(rr.Result().Body)
	if got := strings.TrimSpace(string(b)); got != "good 203.0.113.11" {
		t.Fatalf("basic auth: %q", got)
	}
	// no token at all
	_, body = get(t, h, "/nic/update", nil, "1.2.3.4:1")
	if body != "badauth" {
		t.Fatalf("badauth: %q", body)
	}
}

func TestHealthz(t *testing.T) {
	s, _, _ := newTestServer(t, baseConf)
	code, body := get(t, s.Handler(), "/healthz", nil, "1.2.3.4:1")
	if code != 200 || body != "ok" {
		t.Fatalf("healthz: %d %q", code, body)
	}
}
