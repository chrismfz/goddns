package service

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/named"
	"github.com/chrismfz/goddns/internal/zonemgr"
)

func zoneRig(t *testing.T) (*Service, *named.Inventory, *[]string) {
	t.Helper()
	s, _, lines, _ := newSvc(t, `zone_ns = ["ns1.example.com", "ns2.example.com"]`)
	dir := t.TempDir()
	inv := &named.Inventory{Zones: []named.Zone{{Name: "example.com", Type: "master", Path: "/x"}}}
	s.Inv = func(*config.Config) (*named.Inventory, error) { return inv, nil }
	nc, inc := filepath.Join(dir, "named.conf"), filepath.Join(dir, "goddns-zones.conf")
	os.WriteFile(nc, []byte("include \""+inc+"\";\n"), 0o644)
	s.cfg().ManagedInclude, s.cfg().ManagedZoneDir = inc, filepath.Join(dir, "zones")
	s.ZoneMgr = func(*config.Config) *zonemgr.Manager {
		return &zonemgr.Manager{NamedConf: nc, Include: inc, ZoneDir: filepath.Join(dir, "zones"), LockDir: filepath.Join(dir, "l"),
			Inv: func() (*named.Inventory, error) { return inv, nil }, CheckZone: func(string, []byte) error { return nil },
			CheckConf: func() error { return nil }, Reconfig: func() error { return nil }, Verify: func(string) error { return nil }}
	}
	return s, inv, lines
}

func TestZoneCreateAssignDelete(t *testing.T) {
	s, inv, lines := zoneRig(t)
	s.UserAdd(who, "kim", "kimpass123", RoleUser)
	*lines = nil

	p, err := s.ZoneCreate(who, "Kim.Example.ORG.", nil, "kim", false)
	if err != nil || p.Zone != "kim.example.org" || !strings.Contains(p.Content, "ns2.example.com.") || len(*lines) != 0 {
		t.Fatalf("preview: %+v %v audit=%v", p, err, *lines)
	}
	if _, err := os.Stat(p.File); !os.IsNotExist(err) {
		t.Fatal("preview created the file")
	}
	if g, _ := s.store.GrantsFor("kim"); len(g) != 0 {
		t.Fatal("preview granted the zone")
	}
	p, err = s.ZoneCreate(who, "kim.example.org", nil, "kim", true)
	if err != nil || p.AssignedTo != "kim" {
		t.Fatalf("create: %+v %v", p, err)
	}
	if g, _ := s.store.GrantsFor("kim"); len(g) != 1 || g[0] != "kim.example.org" {
		t.Fatalf("grant: %v", g)
	}
	if !strings.Contains(strings.Join(*lines, "\n"), "zone-create zone=kim.example.org") {
		t.Fatalf("audit: %v", *lines)
	}
	// the zone list marks it as managed; the static editor allows it
	inv.Zones = append(inv.Zones, named.Zone{Name: "kim.example.org", Type: "master", Path: p.File})
	zl, _ := s.Zones(who)
	if !zl.Managed["kim.example.org"] || zl.Managed["example.com"] {
		t.Fatalf("managed: %v", zl.Managed)
	}
	// delete: the grant goes with it
	if _, err := s.ZoneDelete(who, "kim.example.org", true); err != nil {
		t.Fatal(err)
	}
	if g, _ := s.store.GrantsFor("kim"); len(g) != 0 {
		t.Fatalf("grant survived the zone: %v", g)
	}
}

func TestZoneCreateRefusals(t *testing.T) {
	s, _, _ := zoneRig(t)
	user := Actor{User: "x", Role: RoleUser}
	if _, err := s.ZoneCreate(user, "a.example.org", nil, "", false); !IsForbidden(err) {
		t.Fatalf("user creating a zone: %v", err)
	}
	if _, err := s.ZoneDelete(user, "a.example.org", false); !IsForbidden(err) {
		t.Fatalf("user deleting a zone: %v", err)
	}
	if _, err := s.ZoneCreate(who, "example.com", nil, "", false); !IsInvalid(err) {
		t.Fatalf("existing zone must be a 400-class refusal: %v", err)
	}
	if _, err := s.ZoneDelete(who, "example.com", false); !IsInvalid(err) || !strings.Contains(err.Error(), "defined elsewhere") {
		t.Fatalf("deleting an operator zone: %v", err)
	}
	if _, err := s.ZoneCreate(who, "b.example.org", nil, "ghost", false); !IsInvalid(err) {
		t.Fatalf("assign to a missing user: %v", err)
	}
	// a child zone: parent reported
	p, err := s.ZoneCreate(who, "sub.example.com", nil, "", false)
	if err != nil || p.Parent != "example.com" {
		t.Fatalf("child zone: %+v %v", p, err)
	}
}

func TestDDNSRefusesStaticZone(t *testing.T) {
	s, _, _ := zoneRig(t)
	if _, _, err := s.DDNSAdd(who, "home", "example.com", 0); !IsInvalid(err) || !strings.Contains(err.Error(), "static zone") {
		t.Fatalf("DDNS in a static zone: %v", err)
	}
}

func TestIncludeHint(t *testing.T) {
	cfg := &config.Config{ManagedInclude: filepath.Join(t.TempDir(), "missing.conf")}
	err := includeHint(cfg, errors.New("named-checkconf -p: /etc/named.conf:82: parsing failed: file not found"))
	if !strings.Contains(err.Error(), "goddns zone init") {
		t.Fatalf("hint: %v", err)
	}
	other := errors.New("named-checkconf -p: syntax error")
	if includeHint(cfg, other) != other {
		t.Fatal("unrelated errors must pass through")
	}
}
