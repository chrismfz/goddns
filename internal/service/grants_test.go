package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/filezone"
	"github.com/chrismfz/goddns/internal/named"
)

// grantFixture: zones example.com (static, editable), sub.example.com and
// other.net; alice (user) is granted example.com only.
func grantFixture(t *testing.T) (*Service, Actor, *[]string, string) {
	t.Helper()
	s, _, lines, _ := newSvc(t, `editable_zones = ["example.com", "sub.example.com"]`)
	dir := t.TempDir()
	zp := filepath.Join(dir, "example.com.db")
	os.WriteFile(zp, []byte("$ORIGIN example.com.\n$TTL 60\n@ IN SOA ns.example.com. h.example.com. 1 3 4 5 6\n@ IN NS ns.example.com.\nwww IN A 1.1.1.1\n"), 0o640)
	inv := &named.Inventory{Zones: []named.Zone{
		{Name: "example.com", Type: "master", Path: zp},
		{Name: "sub.example.com", Type: "master", Path: filepath.Join(dir, "sub.db")},
		{Name: "other.net", Type: "master", Path: filepath.Join(dir, "other.db")},
	}}
	s.Inv = func(*config.Config) (*named.Inventory, error) { return inv, nil }
	s.FileEd = func(*config.Config) *filezone.Editor {
		return &filezone.Editor{
			Editable: []string{"example.com", "sub.example.com"}, LockDir: filepath.Join(dir, "l"), BackupDir: filepath.Join(dir, "b"),
			Inv:       func() (*named.Inventory, error) { return inv, nil },
			CheckZone: func(string, []byte) error { return nil },
			Reload:    func(string) error { return nil },
			Verify:    func(string, uint32) error { return nil },
		}
	}
	if err := s.UserAdd(who, "alice", "alicepass1", RoleUser); err != nil {
		t.Fatal(err)
	}
	if err := s.Grant(who, "alice", "Example.COM."); err != nil {
		t.Fatal(err)
	}
	*lines = nil
	return s, Actor{User: "alice", Peer: "192.0.2.9", Role: RoleUser}, lines, zp
}

func TestGrantValidation(t *testing.T) {
	s, _, lines, _ := grantFixture(t)
	if err := s.Grant(who, "alice", "nope.example"); !IsInvalid(err) {
		t.Fatalf("a zone BIND doesn't serve must be refused: %v", err)
	}
	if err := s.Grant(who, "ghost", "other.net"); !IsInvalid(err) {
		t.Fatalf("grant to a missing user: %v", err)
	}
	s.cfg().Admin.Users = []string{confAdmin(t, "root", "rootpass1")}
	if err := s.Grant(who, "root", "other.net"); !IsInvalid(err) {
		t.Fatalf("grant to a goddns.conf admin: %v", err)
	}
	if err := s.Revoke(who, "alice", "other.net"); !IsInvalid(err) {
		t.Fatalf("revoking a grant that isn't there: %v", err)
	}
	if z, _ := s.MyZones(Actor{User: "alice", Role: RoleUser}); len(z) != 1 || z[0] != "example.com" {
		t.Fatalf("normalized grant: %v", z)
	}
	if err := s.Revoke(who, "alice", "EXAMPLE.com."); err != nil {
		t.Fatal(err)
	}
	if len(*lines) != 1 || !strings.Contains((*lines)[0], "grant-del user=alice zone=example.com") {
		t.Fatalf("audit: %v", *lines)
	}
}

func TestGrantedUserScope(t *testing.T) {
	s, alice, _, zp := grantFixture(t)

	zl, err := s.Zones(alice)
	if err != nil || len(zl.Zones) != 1 || zl.Zones[0].Name != "example.com" || zl.Keys != nil || zl.Findings != nil || zl.Directory != "" {
		t.Fatalf("zones list for a user: %+v %v", zl, err)
	}
	if _, err := s.NSVerdicts(alice, []named.Zone{{Name: "other.net"}}); !IsForbidden(err) {
		t.Fatalf("NS probe of an ungranted zone: %v", err)
	}
	for _, z := range []string{"other.net", "sub.example.com"} { // a grant is not one on subzones
		if _, err := s.EditRecord(alice, z, ActionAdd, "x 60 IN A 9.9.9.9", true); !IsForbidden(err) {
			t.Errorf("edit %s: %v", z, err)
		}
		if _, err := s.History(alice, z); !IsForbidden(err) {
			t.Errorf("history %s: %v", z, err)
		}
		if _, err := s.Restore(alice, z, 1, false); !IsForbidden(err) {
			t.Errorf("restore %s: %v", z, err)
		}
	}
	// Writing into sub.example.com's namespace THROUGH example.com is refused.
	if _, err := s.EditRecord(alice, "example.com", ActionAdd, "x.sub 60 IN A 9.9.9.9", true); err == nil || !strings.Contains(err.Error(), "more specific zone") {
		t.Fatalf("edit into a child zone via the parent: %v", err)
	}
	// An admin keeps the parent-side delegation records (NS at a child apex).
	if _, err := s.EditRecord(who, "example.com", ActionAdd, "sub 60 IN NS ns1.example.net.", false); err != nil {
		t.Fatalf("admin delegation NS in the parent: %v", err)
	}
	// Its own zone works, in place.
	res, err := s.EditRecord(alice, "example.com", ActionAdd, "new 60 IN A 9.9.9.9", true)
	if err != nil || !res.Static {
		t.Fatalf("edit own zone: %+v %v", res, err)
	}
	if b, _ := os.ReadFile(zp); !strings.Contains(string(b), "9.9.9.9") {
		t.Fatal("own-zone edit not written")
	}
}

func TestGrantedUserDDNS(t *testing.T) {
	s, alice, _, _ := grantFixture(t)
	// admin-owned records in two zones
	if _, _, err := s.DDNSAdd(who, "home.other.net", "other.net", 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.DDNSAdd(who, "home.elsewhere.org", "other.net", 0); !IsInvalid(err) {
		t.Fatalf("an out-of-zone hostname must be refused (even for an admin): %v", err)
	}
	if _, _, err := s.DDNSAdd(alice, "home.other.net", "other.net", 0); !IsForbidden(err) {
		t.Fatalf("add in an ungranted zone: %v", err)
	}
	if _, _, err := s.DDNSAdd(alice, "cam.sub.example.com", "example.com", 0); !IsInvalid(err) {
		t.Fatalf("add a name that belongs to a child zone: %v", err)
	}
	if _, _, err := s.DDNSAdd(alice, "cam.example.com", "example.com", 0); err != nil {
		t.Fatal(err)
	}
	// an admin's record in the granted zone is not the user's to touch
	if _, _, err := s.DDNSAdd(who, "gw.example.com", "example.com", 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.DDNSRotate(alice, "gw.example.com"); !IsForbidden(err) {
		t.Fatalf("user rotated an admin's token: %v", err)
	}
	if err := s.DDNSDel(alice, "gw.example.com"); !IsForbidden(err) {
		t.Fatalf("user deleted an admin's token: %v", err)
	}
	recs, err := s.DDNSList(alice)
	if err != nil || len(recs) != 1 || recs[0].FQDN != "cam.example.com." {
		t.Fatalf("user's DDNS list: %+v %v", recs, err)
	}
	for name, err := range map[string]error{
		"get other":    func() error { _, e := s.DDNSGet(alice, "home.other.net"); return e }(),
		"rotate other": func() error { _, _, e := s.DDNSRotate(alice, "home.other.net"); return e }(),
		"del other":    s.DDNSDel(alice, "home.other.net"),
		"get missing":  func() error { _, e := s.DDNSGet(alice, "ghost.example.com"); return e }(),
	} {
		if !IsForbidden(err) {
			t.Errorf("%s: want ErrForbidden, got %v", name, err)
		}
	}
	if _, _, err := s.DDNSRotate(alice, "cam.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := s.DDNSDel(alice, "cam.example.com"); err != nil {
		t.Fatal(err)
	}
	if all, _ := s.DDNSList(who); len(all) != 2 {
		t.Fatalf("admin's record touched: %+v", all)
	}
}
