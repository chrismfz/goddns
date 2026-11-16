package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/filezone"
	"github.com/chrismfz/goddns/internal/named"
	"github.com/chrismfz/goddns/internal/store"
)

// newSvc builds a Service over a temp store and a parsed config, capturing
// audit lines instead of logging them.
func newSvc(t *testing.T, extra string) (*Service, *store.Store, *[]string, string) {
	t.Helper()
	dir := t.TempDir()
	conf := filepath.Join(dir, "goddns.conf")
	body := "cert_file = \"/tmp/c.pem\"\nkey_file = \"/tmp/k.pem\"\nproxy_enabled = true\n" + extra
	if err := os.WriteFile(conf, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := config.Load(conf)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	st, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := New(func() *config.Config { return c }, st)
	var lines []string
	s.Logf = func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) }
	return s, st, &lines, conf
}

var who = Actor{User: "chris", Peer: "192.0.2.1", Role: RoleAdmin}

func TestDDNSLifecycleAudits(t *testing.T) {
	s, st, lines, _ := newSvc(t, "")
	if _, _, err := s.DDNSAdd(who, " ", "ddns.example", 0); !IsInvalid(err) {
		t.Fatalf("missing fqdn must be InvalidError, got %v", err)
	}
	rec, tok, err := s.DDNSAdd(who, "home.ddns.example", "ddns.example", 0)
	if err != nil {
		t.Fatal(err)
	}
	if rec.TTL != DefaultDDNSTTL || tok == "" {
		t.Fatalf("add: ttl=%d tok=%q", rec.TTL, tok)
	}
	if _, err := st.Lookup(tok); err != nil {
		t.Fatalf("new token must authenticate: %v", err)
	}
	_, tok2, err := s.DDNSRotate(who, "home.ddns.example")
	if err != nil || tok2 == tok {
		t.Fatalf("rotate: %v", err)
	}
	if err := s.DDNSDel(who, "home.ddns.example"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"admin-audit user=chris peer=192.0.2.1 ddns-add fqdn=home.ddns.example. zone=ddns.example. ttl=60",
		"admin-audit user=chris peer=192.0.2.1 ddns-rotate fqdn=home.ddns.example.",
		"admin-audit user=chris peer=192.0.2.1 ddns-del fqdn=home.ddns.example.",
	}
	if strings.Join(*lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("audit lines:\n%s\nwant:\n%s", strings.Join(*lines, "\n"), strings.Join(want, "\n"))
	}
}

func TestEditRecordValidates(t *testing.T) {
	s, _, lines, _ := newSvc(t, "")
	for _, c := range [][3]string{{"", "add", "a 60 IN A 1.1.1.1"}, {"z", "add", ""}, {"z", "upsert", "a 60 IN A 1.1.1.1"}} {
		if _, err := s.EditRecord(who, c[0], c[1], c[2], true); !IsInvalid(err) {
			t.Fatalf("%v: want InvalidError, got %v", c, err)
		}
	}
	if len(*lines) != 0 {
		t.Fatalf("a refused edit must not audit: %v", *lines)
	}
}

// An enabled static zone routes to the in-place editor: preview writes nothing
// and doesn't audit; apply edits the file and audits with via=direct.
func TestEditRecordRoutesStaticZone(t *testing.T) {
	s, _, lines, _ := newSvc(t, `editable_zones = ["example"]`)
	dir := t.TempDir()
	zonePath := filepath.Join(dir, "example.db")
	os.WriteFile(zonePath, []byte("$ORIGIN example.\n$TTL 60\n@ IN SOA ns.example. host.example. 1 3 4 5 6\n@ IN NS ns.example.\nwww IN A 1.1.1.1\n"), 0o640)
	inv := &named.Inventory{Zones: []named.Zone{{Name: "example", Type: "master", Path: zonePath}}}
	s.FileEd = func(*config.Config) *filezone.Editor {
		return &filezone.Editor{
			Editable: []string{"example"}, LockDir: filepath.Join(dir, "l"), BackupDir: filepath.Join(dir, "b"),
			Inv:       func() (*named.Inventory, error) { return inv, nil },
			CheckZone: func(string, []byte) error { return nil },
			Reload:    func(string) error { return nil },
			Verify:    func(string, uint32) error { return nil },
		}
	}
	res, err := s.EditRecord(who, "example", ActionAdd, "new 60 IN A 9.9.9.9", false)
	if err != nil || !res.Static || len(res.Added) != 1 {
		t.Fatalf("preview: %+v %v", res, err)
	}
	if b, _ := os.ReadFile(zonePath); strings.Contains(string(b), "9.9.9.9") || len(*lines) != 0 {
		t.Fatal("preview must neither write nor audit")
	}
	res, err = s.EditRecord(who, "example", ActionAdd, "new 60 IN A 9.9.9.9", true)
	if err != nil || res.Via != "direct" || res.Serial == 0 {
		t.Fatalf("apply: %+v %v", res, err)
	}
	if b, _ := os.ReadFile(zonePath); !strings.Contains(string(b), "9.9.9.9") {
		t.Fatal("apply did not write the zone file")
	}
	if len(*lines) != 1 || !strings.Contains((*lines)[0], "record-add zone=example") || !strings.Contains((*lines)[0], "via=direct") {
		t.Fatalf("audit: %v", *lines)
	}
}

func TestRestoreRefusesForeignSnapshot(t *testing.T) {
	s, st, _, _ := newSvc(t, "")
	id, err := st.SnapshotPut("other.example", 1, "other.example. 60 IN A 1.1.1.1\n", 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Restore(who, "example", id, false); err == nil || !strings.Contains(err.Error(), "no snapshot") {
		t.Fatalf("a snapshot of another zone must be refused, got %v", err)
	}
	if _, err := s.Restore(who, "example", 0, false); !IsInvalid(err) {
		t.Fatalf("id 0 must be InvalidError, got %v", err)
	}
}

func TestVhostSet(t *testing.T) {
	s, _, lines, conf := newSvc(t, `proxy_listen = ":8443"`)
	rule := config.ProxyRule{Upstream: "http://10.0.0.5:80"}
	if _, err := s.VhostSet(who, "nas.example", rule, true); !IsInvalid(err) {
		t.Fatalf("editing off must be InvalidError, got %v", err)
	}
	s.ConfPath = conf
	reloads := 0
	s.Reload = func() { reloads++ }

	bad := rule
	bad.ConsolePorts = []int{8443}
	if _, err := s.VhostSet(who, "nas.example", bad, true); err == nil || !strings.Contains(err.Error(), "collides") {
		t.Fatalf("console port on proxy_listen must be refused, got %v", err)
	}
	res, err := s.VhostSet(who, "nas.example", rule, false)
	if err != nil || res.Action != "add" || reloads != 0 || len(*lines) != 0 {
		t.Fatalf("preview: %+v %v reloads=%d", res, err, reloads)
	}
	if _, err := s.VhostSet(who, "nas.example", rule, true); err != nil {
		t.Fatal(err)
	}
	if reloads != 1 || !s.VhostManaged(who)["nas.example"] {
		t.Fatalf("apply: reloads=%d managed=%v", reloads, s.VhostManaged(who))
	}
	if _, err := s.VhostRemove(who, "nas.example", true); err != nil {
		t.Fatal(err)
	}
	if reloads != 2 || len(*lines) != 2 || !strings.Contains((*lines)[1], "vhost-remove host=nas.example") {
		t.Fatalf("remove: reloads=%d audit=%v", reloads, *lines)
	}
}

// A relative owner qualifies against the zone on every path (it used to become
// a root-level name on the RFC2136 path), and a parse failure is a caller
// mistake, not a missing field.
func TestParseRRQualifiesAgainstZone(t *testing.T) {
	for line, want := range map[string]string{
		"www 60 IN A 203.0.113.9":          "www.example.com.",
		"@ 60 IN TXT \"v=spf1 -all\"":      "example.com.",
		"abs.other.net. 60 IN A 192.0.2.1": "abs.other.net.",
	} {
		rr, err := ParseRR(line, "example.com")
		if err != nil || rr.Header().Name != want {
			t.Fatalf("%q: got %v %v, want owner %s", line, rr, err, want)
		}
	}
	_, err := ParseRR("www 60 IN A not-an-ip", "example.com")
	if !IsInvalid(err) || IsMissing(err) {
		t.Fatalf("bad RR must be InvalidError (not Missing), got %v", err)
	}
}

func TestErrorClassification(t *testing.T) {
	s, st, _, conf := newSvc(t, `proxy_listen = ":8443"`)
	if _, err := s.EditRecord(who, "", ActionAdd, "x", true); !IsMissing(err) {
		t.Fatalf("empty zone must be Missing, got %v", err)
	}
	id, _ := st.SnapshotPut("other.example", 1, "x", 10)
	if _, err := s.Restore(who, "example", id, false); !IsInvalid(err) || IsMissing(err) {
		t.Fatalf("foreign snapshot must be InvalidError (not Missing), got %v", err)
	}
	s.ConfPath = conf
	if _, err := s.VhostSet(who, "a.example", config.ProxyRule{Upstream: "http://x", ConsolePorts: []int{8443}}, false); !IsInvalid(err) {
		t.Fatalf("collision must be InvalidError, got %v", err)
	}
	if _, err := s.VhostGet(who, "nope.example"); !IsInvalid(err) {
		t.Fatalf("unknown vhost must be InvalidError, got %v", err)
	}
}

// Every vhost entry point normalizes the host the same way.
func TestVhostHostNormalized(t *testing.T) {
	s, _, lines, conf := newSvc(t, "")
	s.ConfPath = conf
	if _, err := s.VhostSet(who, " NAS.Example. ", config.ProxyRule{Upstream: "http://10.0.0.5:80"}, true); err != nil {
		t.Fatal(err)
	}
	if e, err := s.VhostGet(who, "nas.example"); err != nil || e.Host != "nas.example" {
		t.Fatalf("get: %+v %v", e, err)
	}
	if _, err := s.VhostRemove(who, "Nas.EXAMPLE.", true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains((*lines)[0], "host=nas.example ") || !strings.Contains((*lines)[1], "host=nas.example") {
		t.Fatalf("audit hosts not normalized: %v", *lines)
	}
}

func TestQualifyName(t *testing.T) {
	for in, want := range map[string]string{
		"test":                  "test.ddns.example.com.",
		"a.b":                   "a.b.ddns.example.com.",
		"@":                     "ddns.example.com.",
		"":                      "ddns.example.com.",
		"test.ddns.example.com": "test.ddns.example.com.", // the live-test trap: not x.zone.zone
		"Test.DDNS.example.com": "Test.DDNS.example.com.",
		"ddns.example.com":      "ddns.example.com.",
		"other.net.":            "other.net.",
		"xddns.example.com":     "xddns.example.com.ddns.example.com.", // label boundary, not a suffix match
	} {
		if got := QualifyName(in, "DDNS.example.com."); got != want {
			t.Errorf("QualifyName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDDNSAddRelativeName(t *testing.T) {
	s, _, _, _ := newSvc(t, "")
	rec, _, err := s.DDNSAdd(who, "home", "ddns.example.com", 0)
	if err != nil || rec.FQDN != "home.ddns.example.com." {
		t.Fatalf("relative: %+v %v", rec, err)
	}
	rec, _, err = s.DDNSAdd(who, "@", "ddns.example.com", 0)
	if err != nil || rec.FQDN != "ddns.example.com." {
		t.Fatalf("apex: %+v %v", rec, err)
	}
	if _, _, err := s.DDNSAdd(who, "x.other.net.", "ddns.example.com", 0); !IsInvalid(err) {
		t.Fatalf("an absolute name outside the zone stays refused: %v", err)
	}
}
