package server

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/chrismfz/goddns/internal/config"
)

// update_log decides which update results get a line (issue #63); the token
// never appears, and a client-chosen value can't forge fields.
func TestUpdateLogLevels(t *testing.T) {
	var buf bytes.Buffer
	run := func(level string) string {
		buf.Reset()
		s, st, _ := newTestServer(t, baseConf+"update_log = \""+level+"\"\n")
		s.Logf = func(f string, a ...any) { fmt.Fprintf(&buf, f+"\n", a...) }
		_, tok, err := st.Add("home.myip.gr", "myip.gr", 60)
		if err != nil {
			t.Fatal(err)
		}
		h := s.Handler()
		get(t, h, "/update/"+tok+"?ip=203.0.113.5", nil, "198.51.100.1:1")                // good
		get(t, h, "/update/"+tok+"?ip=203.0.113.5", nil, "198.51.100.1:1")                // nochg
		get(t, h, "/update/not-a-token", nil, "198.51.100.2:1")                           // badauth
		get(t, h, "/update/"+tok+"?ip=bogus%20result=good", nil, "198.51.100.3:1")        // badip
		get(t, h, "/nic/update?hostname=other.myip.gr&token="+tok, nil, "198.51.100.4:1") // nohost
		if strings.Contains(buf.String(), tok) {
			t.Fatalf("%s: the token reached the log", level)
		}
		return buf.String()
	}
	has := func(out, s string) bool { return strings.Contains(out, s) }

	out := run("updates") // default, historical behaviour
	if !has(out, "updated home.myip.gr. -> 203.0.113.5") || has(out, "result=") {
		t.Fatalf("updates:\n%s", out)
	}
	out = run("changes")
	if !has(out, "updated home.myip.gr.") || !has(out, "result=badauth proto=simple peer=198.51.100.2 fqdn=- ip=-") ||
		!has(out, "result=badip") || !has(out, "result=nohost proto=dyndns2") || has(out, "result=nochg") {
		t.Fatalf("changes:\n%s", out)
	}
	// the crafted "bogus result=good" stays inside the quoted detail
	if strings.Count(out, "update result=") != 3 || !has(out, `detail="invalid ip \"bogus result=good\""`) {
		t.Fatalf("changes: a crafted ip= forged a field or the count is off:\n%s", out)
	}
	out = run("all")
	if !has(out, "result=nochg proto=simple peer=198.51.100.1 fqdn=home.myip.gr. ip=203.0.113.5") {
		t.Fatalf("all:\n%s", out)
	}
	out = run("none")
	if has(out, "updated ") || has(out, "result=") {
		t.Fatalf("none:\n%s", out)
	}
}

func TestUpdateLogRejectsUnknownLevel(t *testing.T) {
	p := t.TempDir() + "/goddns.conf"
	os.WriteFile(p, []byte(baseConf+"update_log = \"verbose\"\n"), 0o600)
	if _, err := loadForTest(p); err == nil || !strings.Contains(err.Error(), "update_log") {
		t.Fatalf("want an update_log error, got %v", err)
	}
}

func loadForTest(p string) (any, error) { return config.Load(p) }

// A flood of unauthenticated requests writes at most maxResultLinesPerSec
// result lines a second plus one summary, and a client behind a trusted
// proxy is named in the line (not the proxy).
func TestUpdateLogRateLimitAndProxiedPeer(t *testing.T) {
	var buf bytes.Buffer
	s, _, _ := newTestServer(t, baseConf+"update_log = \"changes\"\ntrusted_proxies = [\"127.0.0.1/32\"]\n")
	s.Logf = func(f string, a ...any) { fmt.Fprintf(&buf, f+"\n", a...) }
	h := s.Handler()
	get(t, h, "/update/guess", map[string]string{"X-Forwarded-For": "203.0.113.77"}, "127.0.0.1:1")
	if !strings.Contains(buf.String(), "peer=203.0.113.77 via=127.0.0.1") {
		t.Fatalf("proxied client not named: %s", buf.String())
	}
	buf.Reset()
	sec := int64(1000)
	s.now = func() int64 { return sec }
	for i := 0; i < 200; i++ {
		if s.allowResult() {
			s.logf("line")
		}
	}
	if n := strings.Count(buf.String(), "line\n"); n != maxResultLinesPerSec {
		t.Fatalf("burst wrote %d lines, want %d", n, maxResultLinesPerSec)
	}
	sec++ // the next second starts a new window and summarises
	s.allowResult()
	if !strings.Contains(buf.String(), "180 result lines suppressed") {
		t.Fatalf("no summary: %s", buf.String())
	}
}
