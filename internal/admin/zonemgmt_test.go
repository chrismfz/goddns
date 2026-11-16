package admin

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/named"
	"github.com/chrismfz/goddns/internal/zonemgr"
)

func TestZoneCreateDeleteUI(t *testing.T) {
	c := mkConfig(t, "")
	c.ZoneNS = []string{"ns1.example.com"}
	h, _ := newHandler(t, c)
	dir := t.TempDir()
	inv := &named.Inventory{Zones: []named.Zone{{Name: "example.com", Type: "master", Path: "/x"}}}
	nc, inc := filepath.Join(dir, "named.conf"), filepath.Join(dir, "goddns-zones.conf")
	os.WriteFile(nc, []byte("include \""+inc+"\";\n"), 0o644)
	c.ManagedInclude = inc
	h.svc.Inv = func(*config.Config) (*named.Inventory, error) { return inv, nil }
	h.svc.ZoneMgr = func(*config.Config) *zonemgr.Manager {
		return &zonemgr.Manager{NamedConf: nc, Include: inc, ZoneDir: filepath.Join(dir, "zones"), LockDir: filepath.Join(dir, "l"),
			Inv: func() (*named.Inventory, error) { return inv, nil }, CheckZone: func(string, []byte) error { return nil },
			CheckConf: func() error { return nil }, Reconfig: func() error { return nil }, Verify: func(string) error { return nil }}
	}
	admin := login(t, h)
	csrf := h.csrfFor("admin")

	page := do(h, "GET", "/zones", "127.0.0.1:1", nil, admin).Body.String()
	if !strings.Contains(page, `action="/zones/create"`) || !strings.Contains(page, `value="ns1.example.com"`) {
		t.Fatal("zones page lacks the create form / zone_ns default")
	}
	rr := do(h, "POST", "/zones/create", "127.0.0.1:1", map[string]string{"csrf": csrf, "zone": "sub.example.com", "ns": "ns1.example.com"}, admin)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), "inside <b>example.com</b>") || !strings.Contains(rr.Body.String(), "yes, create it") {
		t.Fatalf("preview: %d", rr.Code)
	}
	if _, err := os.Stat(inc); !os.IsNotExist(err) {
		t.Fatal("preview wrote the include")
	}
	rr = do(h, "POST", "/zones/create", "127.0.0.1:1", map[string]string{"csrf": csrf, "zone": "sub.example.com", "ns": "ns1.example.com", "confirm": "1"}, admin)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	if z, _ := zonemgr.ManagedZones(inc); len(z) != 1 || z[0] != "sub.example.com" {
		t.Fatalf("include: %v", z)
	}
	inv.Zones = append(inv.Zones, named.Zone{Name: "sub.example.com", Type: "master", Path: filepath.Join(dir, "zones", "sub.example.com.hosts")})
	if page := do(h, "GET", "/zones", "127.0.0.1:1", nil, admin).Body.String(); !strings.Contains(page, `action="/zones/delete"`) {
		t.Fatal("managed zone has no delete button")
	}
	// an operator's zone can't be deleted here
	if rr := do(h, "POST", "/zones/delete", "127.0.0.1:1", map[string]string{"csrf": csrf, "zone": "example.com"}, admin); !strings.Contains(rr.Body.String(), "defined elsewhere") {
		t.Fatalf("operator zone delete: %d %s", rr.Code, rr.Body.String())
	}
	rr = do(h, "POST", "/zones/delete", "127.0.0.1:1", map[string]string{"csrf": csrf, "zone": "sub.example.com", "confirm": "1"}, admin)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("delete: %d", rr.Code)
	}
	if z, _ := zonemgr.ManagedZones(inc); len(z) != 0 {
		t.Fatalf("after delete: %v", z)
	}
	// a user role never reaches these
	do(h, "POST", "/users", "127.0.0.1:1", map[string]string{"csrf": csrf, "op": "add", "name": "lee", "pass": "leepass123", "role": "user"}, admin)
	lee := loginAs(t, h, "lee", "leepass123")
	if rr := do(h, "POST", "/zones/create", "127.0.0.1:1", map[string]string{"csrf": h.csrfFor("lee"), "zone": "x.example.org"}, lee); rr.Code != http.StatusForbidden {
		t.Fatalf("user create: %d", rr.Code)
	}
}
