package zonemgr

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chrismfz/goddns/internal/named"
)

type rig struct {
	m         *Manager
	inv       *named.Inventory
	confErr   error
	verifyErr error
	reconfig  int
}

func newRig(t *testing.T) *rig {
	t.Helper()
	dir := t.TempDir()
	r := &rig{inv: &named.Inventory{Zones: []named.Zone{
		{Name: "example.com", Type: "master", Path: "/var/named/example.com.hosts"},
		{Name: "ddns.example.com", Type: "master", Dynamic: true},
	}}}
	inc := filepath.Join(dir, "goddns-zones.conf")
	nc := filepath.Join(dir, "named.conf")
	os.WriteFile(nc, []byte("options { };\ninclude \""+inc+"\";\n"), 0o644)
	r.m = &Manager{
		NamedConf: nc, Include: inc, ZoneDir: filepath.Join(dir, "zones"), LockDir: filepath.Join(dir, "locks"),
		Inv:       func() (*named.Inventory, error) { return r.inv, nil },
		CheckZone: func(string, []byte) error { return nil },
		CheckConf: func() error { return r.confErr },
		Reconfig:  func() error { r.reconfig++; return nil },
		Verify:    func(string) error { return r.verifyErr },
		Now:       func() time.Time { return time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC) },
	}
	return r
}

func TestCreateAndDelete(t *testing.T) {
	r := newRig(t)
	req := CreateRequest{Zone: "Zone.DDNS.example.com.", NS: []string{"ns1.example.com", "ns2.example.net."}}
	p, err := r.m.PlanCreate(req)
	if err != nil {
		t.Fatal(err)
	}
	if p.Zone != "zone.ddns.example.com" || p.Parent != "ddns.example.com" || r.reconfig != 0 {
		t.Fatalf("plan: %+v", p)
	}
	if _, err := os.Stat(p.File); !os.IsNotExist(err) {
		t.Fatal("PlanCreate wrote the zone file")
	}
	if !strings.Contains(p.Content, "@\tIN\tSOA\tns1.example.com. hostmaster.zone.ddns.example.com. 2026111601 ") ||
		strings.Count(p.Content, "IN\tNS") != 2 {
		t.Fatalf("content:\n%s", p.Content)
	}
	if _, err := r.m.Create(req); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p.File); string(b) != p.Content {
		t.Fatal("zone file not written")
	}
	if z, _ := ManagedZones(r.m.Include); len(z) != 1 || z[0] != "zone.ddns.example.com" || r.reconfig != 1 {
		t.Fatalf("include: %v reconfig=%d", z, r.reconfig)
	}
	// it now exists: a second create is refused
	r.inv.Zones = append(r.inv.Zones, named.Zone{Name: "zone.ddns.example.com", Type: "master", Path: p.File})
	if _, err := r.m.PlanCreate(req); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("duplicate: %v", err)
	}
	// a hand-added stanza in the include is kept by a later delete
	b, _ := os.ReadFile(r.m.Include)
	os.WriteFile(r.m.Include, append(b, []byte("zone \"hand.example\" {\n\ttype master;\n\tfile \"/x/hand\";\n};\n")...), 0o640)
	dp, err := r.m.Delete("zone.ddns.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(dp.MovedTo, ".deleted-20261116-120000") {
		t.Fatalf("moved to %q", dp.MovedTo)
	}
	if _, err := os.Stat(p.File); !os.IsNotExist(err) {
		t.Fatal("zone file still in place")
	}
	if z, _ := ManagedZones(r.m.Include); len(z) != 1 || z[0] != "hand.example" {
		t.Fatalf("after delete: %v", z)
	}
}

func TestCreateRollsBackOnCheckconf(t *testing.T) {
	r := newRig(t)
	r.confErr = errors.New("zone.conf:3: unknown option")
	_, err := r.m.Create(CreateRequest{Zone: "new.example.org", NS: []string{"ns1.example.com"}})
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("want rollback, got %v", err)
	}
	if _, err := os.Stat(r.m.Include); !os.IsNotExist(err) {
		t.Fatal("include left behind after a rejected create")
	}
	if _, err := os.Stat(r.m.zoneFile("new.example.org")); !os.IsNotExist(err) {
		t.Fatal("zone file left behind")
	}
	if r.reconfig != 0 {
		t.Fatal("BIND reconfigured with a rejected config")
	}
}

func TestDeleteRefusesForeignZones(t *testing.T) {
	r := newRig(t)
	if _, err := r.m.Delete("example.com"); err == nil || !strings.Contains(err.Error(), "defined elsewhere") {
		t.Fatalf("deleting an operator zone: %v", err)
	}
}

func TestCreateValidation(t *testing.T) {
	r := newRig(t)
	for _, z := range []string{"../etc/passwd", "a", "x\"; };", "-bad.example", "a..b"} {
		if _, err := r.m.PlanCreate(CreateRequest{Zone: z, NS: []string{"ns1.example.com"}}); err == nil {
			t.Errorf("zone %q accepted", z)
		}
	}
	if _, err := r.m.PlanCreate(CreateRequest{Zone: "ok.example.org"}); err == nil {
		t.Error("no nameserver accepted")
	}
	os.MkdirAll(r.m.ZoneDir, 0o750)
	os.WriteFile(r.m.zoneFile("taken.example.org"), []byte("x"), 0o640)
	if _, err := r.m.PlanCreate(CreateRequest{Zone: "taken.example.org", NS: []string{"ns1.example.com"}}); err == nil {
		t.Error("existing zone file overwritten")
	}
	// the include not referenced from named.conf
	os.WriteFile(r.m.NamedConf, []byte("options { };\n"), 0o644)
	if _, err := r.m.PlanCreate(CreateRequest{Zone: "ok.example.org", NS: []string{"ns1.example.com"}}); err == nil || !strings.Contains(err.Error(), "include") {
		t.Errorf("unreferenced include: %v", err)
	}
}

// named-checkconf passes but named doesn't serve the zone (a file it can't
// read): the create is rolled back, not reported as done.
func TestCreateRollsBackWhenNamedDoesNotLoad(t *testing.T) {
	r := newRig(t)
	r.verifyErr = errors.New("answered SERVFAIL")
	if _, err := r.m.Create(CreateRequest{Zone: "new.example.org", NS: []string{"ns1.example.com"}}); err == nil || !strings.Contains(err.Error(), "did not load") {
		t.Fatalf("want a load failure, got %v", err)
	}
	if _, err := os.Stat(r.m.zoneFile("new.example.org")); !os.IsNotExist(err) {
		t.Fatal("zone file left behind")
	}
	if z, _ := ManagedZones(r.m.Include); len(z) != 0 {
		t.Fatalf("stanza left behind: %v", z)
	}
}

func TestStrictNSAndDeleteOutsideZoneDir(t *testing.T) {
	r := newRig(t)
	for _, ns := range []string{"ns1.example.com.\nevil 60 IN A 203.0.113.66", "ns 1.example.com", "ns1.example.com;x", "localhost"} {
		if _, err := r.m.PlanCreate(CreateRequest{Zone: "x.example.org", NS: []string{ns}}); err == nil {
			t.Errorf("NS %q accepted", ns)
		}
	}
	if _, err := r.m.PlanCreate(CreateRequest{Zone: "x.example.org", NS: []string{"ns1.example.com"}, Hostmaster: "a\nb.example.com"}); err == nil {
		t.Error("hostmaster with a newline accepted")
	}
	// a hand-edited stanza pointing outside the zone dir: the file is left alone
	outside := filepath.Join(t.TempDir(), "precious.conf")
	os.WriteFile(outside, []byte("keep"), 0o640)
	os.WriteFile(r.m.Include, []byte("zone \"h.example\" { type master; file \""+outside+"\"; };\n"), 0o640)
	p, err := r.m.Delete("h.example")
	if err != nil {
		t.Fatal(err)
	}
	if p.MovedTo != "" {
		t.Fatalf("moved a file outside managed_zone_dir: %q", p.MovedTo)
	}
	if b, _ := os.ReadFile(outside); string(b) != "keep" {
		t.Fatal("the outside file was touched")
	}
}

func TestCreateRefusesViews(t *testing.T) {
	r := newRig(t)
	r.inv.Zones = append(r.inv.Zones, named.Zone{Name: "int.example.com", Type: "master", View: "internal"})
	if _, err := r.m.PlanCreate(CreateRequest{Zone: "x.example.org", NS: []string{"ns1.example.com"}}); !IsRefused(err) || !strings.Contains(err.Error(), "views") {
		t.Fatalf("views: %v", err)
	}
}

func TestInitCreatesEmptyIncludeOnce(t *testing.T) {
	r := newRig(t)
	created, err := r.m.Init()
	if err != nil || !created {
		t.Fatalf("init: %v %v", created, err)
	}
	if z, err := ManagedZones(r.m.Include); err != nil || len(z) != 0 {
		t.Fatalf("a fresh include must parse as empty: %v %v", z, err)
	}
	os.WriteFile(r.m.Include, []byte("zone \"keep.example\" { type master; file \"x\"; };\n"), 0o640)
	if created, _ := r.m.Init(); created {
		t.Fatal("init overwrote an existing include")
	}
	if z, _ := ManagedZones(r.m.Include); len(z) != 1 {
		t.Fatal("existing include changed")
	}
}

func TestCreateUsesDefaultHostmaster(t *testing.T) {
	r := newRig(t)
	r.m.Hostmaster = "admin@example.com"
	p, err := r.m.PlanCreate(CreateRequest{Zone: "h.example.org", NS: []string{"ns1.example.com"}})
	if err != nil || !strings.Contains(p.Content, " admin.example.com. ") {
		t.Fatalf("hostmaster: %v\n%s", err, p.Content)
	}
}

func TestExplainCheckConf(t *testing.T) {
	r := newRig(t) // named.conf includes r.m.Include, which doesn't exist yet
	bind := errors.New("named-checkconf -p: named.conf:2: parsing failed: file not found")
	if err := ExplainCheckConf(bind, r.m.NamedConf, r.m.Include); !strings.Contains(err.Error(), "goddns zone init") {
		t.Fatalf("our missing include: %v", err)
	}
	other := filepath.Join(t.TempDir(), "other.conf") // not referenced from named.conf
	if err := ExplainCheckConf(bind, r.m.NamedConf, other); err != bind {
		t.Fatalf("another missing file must not be blamed on goddns: %v", err)
	}
	r.m.Init()
	if err := ExplainCheckConf(bind, r.m.NamedConf, r.m.Include); err != bind {
		t.Fatalf("include exists: %v", err)
	}
	syntax := errors.New("named-checkconf -p: syntax error")
	if ExplainCheckConf(syntax, r.m.NamedConf, r.m.Include) != syntax || ExplainCheckConf(nil, "", "") != nil {
		t.Fatal("unrelated errors / nil must pass through")
	}
}

func TestInitRefusesMissingDirectory(t *testing.T) {
	r := newRig(t)
	r.m.Include = filepath.Join(t.TempDir(), "no-such-dir", "goddns-zones.conf")
	if _, err := r.m.Init(); !IsRefused(err) {
		t.Fatalf("missing parent dir: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(r.m.Include)); !os.IsNotExist(err) {
		t.Fatal("Init created the directory")
	}
}
