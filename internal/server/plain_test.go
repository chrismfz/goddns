package server

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// tls_mode = "none" on a unix socket: plain HTTP, the socket is 0666, a stale
// socket is replaced, and the proxy's X-Forwarded-For names the client whose
// IP gets registered (issue #60).
func TestPlainUnixSocketBehindProxy(t *testing.T) {
	dir, err := os.MkdirTemp("", "gd") // short path: sun_path is ~107 bytes
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "g.sock")
	s, st, fb := newTestServer(t, "tls_mode = \"none\"\nlisten = \"unix:"+sock+"\"\n")
	_, tok, _ := st.Add("home.myip.gr", "myip.gr", 60)

	// a stale socket from a previous run is replaced
	old, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	old.(*net.UnixListener).SetUnlinkOnClose(false)
	old.Close()

	ln, err := Listen(s.Cfg())
	if err != nil {
		t.Fatalf("listen over a stale socket: %v", err)
	}
	if fi, _ := os.Stat(sock); fi.Mode().Perm() != 0o666 {
		t.Fatalf("socket mode %v", fi.Mode().Perm())
	}
	srv := &http.Server{Handler: s.Handler()}
	go srv.Serve(ln)
	defer srv.Shutdown(context.Background())

	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", sock)
		},
	}}
	req, _ := http.NewRequest("GET", "http://goddns/update/"+tok, nil)
	req.Header.Set("X-Forwarded-For", "198.51.100.7, 203.0.113.44")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.TrimSpace(string(b)) != "good 203.0.113.44" || len(fb.calls) != 1 {
		t.Fatalf("got %q, calls %v (want the client the proxy appended)", b, fb.calls)
	}

	// no X-Forwarded-For over the socket: no peer IP to fall back on
	req, _ = http.NewRequest("GET", "http://goddns/update/"+tok, nil)
	resp, err = c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(b), "badip") {
		t.Fatalf("no XFF over a socket: %q", b)
	}
}

func TestListenRefusesNonSocketPath(t *testing.T) {
	dir, _ := os.MkdirTemp("", "gd")
	defer os.RemoveAll(dir)
	p := filepath.Join(dir, "notasock")
	os.WriteFile(p, []byte("x"), 0o600)
	s, _, _ := newTestServer(t, "tls_mode = \"none\"\nlisten = \"unix:"+p+"\"\n")
	if _, err := Listen(s.Cfg()); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("a regular file must not be removed: %v", err)
	}
	if b, _ := os.ReadFile(p); string(b) != "x" {
		t.Fatal("the file was touched")
	}
}

// On loopback TCP the same: the peer is the proxy, its X-Forwarded-For names
// the client, without listing 127.0.0.1 in trusted_proxies.
func TestPlainLoopbackTrustsProxy(t *testing.T) {
	s, st, _ := newTestServer(t, "tls_mode = \"none\"\nlisten = \"127.0.0.1:8245\"\n")
	_, tok, _ := st.Add("home.myip.gr", "myip.gr", 60)
	code, body := get(t, s.Handler(), "/update/"+tok, map[string]string{"X-Forwarded-For": "203.0.113.45"}, "127.0.0.1:5555")
	if code != 200 || body != "good 203.0.113.45" {
		t.Fatalf("%d %q", code, body)
	}
}
