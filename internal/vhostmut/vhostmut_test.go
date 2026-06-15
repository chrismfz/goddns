package vhostmut

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"

	"github.com/chrismfz/goddns/internal/config"
)

// newEditor writes a base goddns.conf with the given body and returns an Editor
// rooted next to it (proxy.d/ alongside).
func newEditor(t *testing.T, baseBody string) *Editor {
	t.Helper()
	dir := t.TempDir()
	conf := filepath.Join(dir, "goddns.conf")
	if err := os.WriteFile(conf, []byte(baseBody), 0o640); err != nil {
		t.Fatal(err)
	}
	return &Editor{ConfPath: conf}
}

func rule() config.ProxyRule {
	return config.ProxyRule{Upstream: "https://10.0.0.5", Allow: []string{"10.0.0.0/8"}, RateLimit: 5}
}

func TestSetCreatesManagedFragment(t *testing.T) {
	// a base config that passes full validation, so config.Load below exercises
	// the real merge path rather than tripping on unrelated TLS validation.
	e := newEditor(t, "tls_mode = \"files\"\ncert_file = \"/x/cert.pem\"\nkey_file = \"/x/key.pem\"\n")
	res, err := e.Set("idrac.internal.myip.gr", rule())
	if err != nil {
		t.Fatalf("Set: %v", err)
	}
	if res.Action != "add" {
		t.Fatalf("action = %q, want add", res.Action)
	}
	if filepath.Base(res.File) != "idrac.internal.myip.gr.conf" {
		t.Fatalf("fragment file = %s", res.File)
	}
	// the fragment must parse back to the same vhost+upstream
	var f struct {
		Proxy map[string]config.ProxyRule `toml:"proxy"`
	}
	if _, err := toml.DecodeFile(res.File, &f); err != nil {
		t.Fatalf("rendered fragment doesn't parse: %v", err)
	}
	pr, ok := f.Proxy["idrac.internal.myip.gr"]
	if !ok || pr.Upstream != "https://10.0.0.5" || pr.RateLimit != 5 {
		t.Fatalf("round-trip mismatch: %+v", f.Proxy)
	}

	// a second Set is an update of the same file
	res2, err := e.Set("idrac.internal.myip.gr", rule())
	if err != nil || res2.Action != "update" {
		t.Fatalf("second Set action = %q err=%v, want update", res2.Action, err)
	}

	// the real loader (merge + strict Undecoded check) must accept the fragment
	// and surface the vhost — what we write is exactly what the daemon reads.
	cfg, err := config.Load(e.ConfPath)
	if err != nil {
		t.Fatalf("config.Load rejected the written fragment: %v", err)
	}
	if _, ok := cfg.Proxy["idrac.internal.myip.gr"]; !ok {
		t.Fatalf("loaded config is missing the vhost we wrote: %v", cfg.Proxy)
	}
}

func TestSetRefusesBaseConfigVhost(t *testing.T) {
	// host lives in the hand-edited goddns.conf -> goddns must not override it
	e := newEditor(t, `[proxy."idrac.internal.myip.gr"]
upstream = "https://1.1.1.1"
`)
	if _, err := e.Set("idrac.internal.myip.gr", rule()); err == nil ||
		!strings.Contains(err.Error(), "goddns.conf") {
		t.Fatalf("expected refusal for a base-config vhost, got %v", err)
	}
	// and Remove must refuse it too
	if _, err := e.Remove("idrac.internal.myip.gr"); err == nil ||
		!strings.Contains(err.Error(), "goddns.conf") {
		t.Fatalf("expected Remove refusal for a base-config vhost, got %v", err)
	}
}

// A hand-made fragment named like one goddns would write (proxy.d/<host>.conf)
// but containing MORE than that one host must NOT be treated as managed —
// overwriting/deleting it would silently destroy the other vhosts.
func TestForeignMultiHostFragmentRefused(t *testing.T) {
	e := newEditor(t, "")
	// craft proxy.d/idrac.x.conf defining idrac.x AND cam.y by hand
	frag := filepath.Join(e.dir(), "idrac.x.conf")
	if err := os.MkdirAll(e.dir(), 0o750); err != nil {
		t.Fatal(err)
	}
	body := `[proxy."idrac.x"]
upstream = "https://1.1.1.1"
[proxy."cam.y"]
upstream = "https://2.2.2.2"
`
	if err := os.WriteFile(frag, []byte(body), 0o640); err != nil {
		t.Fatal(err)
	}
	// Set must refuse (not clobber the file and lose cam.y)
	if _, err := e.Set("idrac.x", rule()); err == nil ||
		!strings.Contains(err.Error(), "won't override") {
		t.Fatalf("Set on a foreign multi-host fragment must be refused, got %v", err)
	}
	// Remove must refuse (not delete the whole file)
	if _, err := e.Remove("idrac.x"); err == nil ||
		!strings.Contains(err.Error(), "doesn't manage") {
		t.Fatalf("Remove on a foreign multi-host fragment must be refused, got %v", err)
	}
	// and the file is still intact with both hosts
	got, err := os.ReadFile(frag)
	if err != nil || !strings.Contains(string(got), "cam.y") {
		t.Fatalf("foreign fragment was damaged: %q (err %v)", got, err)
	}
}

func TestRemoveRejectsInvalidHost(t *testing.T) {
	e := newEditor(t, "")
	if _, err := e.Remove("../../etc/passwd"); err == nil ||
		!strings.Contains(err.Error(), "invalid vhost") {
		t.Fatalf("Remove must reject a traversal-shaped host, got %v", err)
	}
}

func TestRemoveManaged(t *testing.T) {
	e := newEditor(t, "")
	if _, err := e.Set("cam.internal.myip.gr", rule()); err != nil {
		t.Fatal(err)
	}
	res, err := e.Remove("cam.internal.myip.gr")
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(res.File); !os.IsNotExist(err) {
		t.Fatalf("fragment still present after Remove: %v", err)
	}
	// removing again -> no managed vhost
	if _, err := e.Remove("cam.internal.myip.gr"); err == nil ||
		!strings.Contains(err.Error(), "no goddns-managed") {
		t.Fatalf("expected not-found on second Remove, got %v", err)
	}
}

func TestSetRejectsInvalidHostAndUpstream(t *testing.T) {
	e := newEditor(t, "")
	if _, err := e.Set("bad/host", rule()); err == nil {
		t.Errorf("a host with a slash must be rejected (path-traversal safety)")
	}
	if _, err := e.Set("ok.example", config.ProxyRule{Upstream: "ftp://x"}); err == nil {
		t.Errorf("a non-http(s) upstream must be rejected")
	}
	if _, err := e.Set("ok.example", config.ProxyRule{Upstream: "https://x", BasicAuth: []string{"user:notbcrypt"}}); err == nil {
		t.Errorf("a non-bcrypt basic_auth entry must be rejected")
	}
	if _, err := e.Set("ok.example", config.ProxyRule{Upstream: "https://x/some/path"}); err == nil {
		t.Errorf("an upstream with a path must be rejected")
	}
}

func TestListProvenance(t *testing.T) {
	e := newEditor(t, `[proxy."base.example"]
upstream = "https://1.1.1.1"
`)
	if _, err := e.Set("managed.example", rule()); err != nil {
		t.Fatal(err)
	}
	entries, err := e.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	got := map[string]bool{}
	for _, en := range entries {
		got[en.Host] = en.Managed
	}
	if managed, ok := got["base.example"]; !ok || managed {
		t.Errorf("base.example should be listed unmanaged, got ok=%v managed=%v", ok, managed)
	}
	if managed, ok := got["managed.example"]; !ok || !managed {
		t.Errorf("managed.example should be listed managed, got ok=%v managed=%v", ok, managed)
	}
}

func TestRenderFragmentOmitsEmptyFields(t *testing.T) {
	out := renderFragment("x.example", config.ProxyRule{Upstream: "https://1.1.1.1"})
	if strings.Contains(out, "allow") || strings.Contains(out, "basic_auth") || strings.Contains(out, "rate_limit") {
		t.Fatalf("empty optional fields should be omitted:\n%s", out)
	}
	if !strings.Contains(out, "Managed by goddns") {
		t.Fatalf("fragment should carry the managed-by marker:\n%s", out)
	}
}
