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
	m        *Manager
	inv      *named.Inventory
	confErr  error
	reconfig int
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
