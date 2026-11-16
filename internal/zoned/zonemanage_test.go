package zoned

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chrismfz/goddns/internal/config"
	"github.com/chrismfz/goddns/internal/named"
	"github.com/chrismfz/goddns/internal/zonemgr"
)

// zone-create / zone-delete through the helper: a preview writes nothing, an
// apply creates the file and stanza, and a refusal comes back flagged so the
// daemon can answer 400 rather than 500.
func TestZonedZoneCreateDelete(t *testing.T) {
	dir := t.TempDir()
	nc, inc := filepath.Join(dir, "named.conf"), filepath.Join(dir, "goddns-zones.conf")
	os.WriteFile(nc, []byte("include \""+inc+"\";\n"), 0o644)
	inv := &named.Inventory{Zones: []named.Zone{{Name: "example.com", Type: "master", Path: "/x"}}}
	cfg := &config.Config{}
	srv := &Server{
		Cfg: func() (*config.Config, error) { return cfg, nil },
		zoneMgr: func(*config.Config) *zonemgr.Manager {
			return &zonemgr.Manager{NamedConf: nc, Include: inc, ZoneDir: filepath.Join(dir, "z"), LockDir: filepath.Join(dir, "l"),
				Inv: func() (*named.Inventory, error) { return inv, nil }, CheckZone: func(string, []byte) error { return nil },
				CheckConf: func() error { return nil }, Reconfig: func() error { return nil }, Verify: func(string) error { return nil }}
		},
	}
	sock := filepath.Join(dir, "zoned.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx, ln)

	resp, err := Call(sock, Request{Zone: "new.example.org", Action: "zone-create", NS: []string{"ns1.example.com"}})
	if err != nil || !strings.Contains(resp.Content, "SOA") {
		t.Fatalf("preview: %+v %v", resp, err)
	}
	if _, err := os.Stat(inc); !os.IsNotExist(err) {
		t.Fatal("preview wrote the include")
	}
	if _, err := Call(sock, Request{Zone: "new.example.org", Action: "zone-create", NS: []string{"ns1.example.com"}, Apply: true}); err != nil {
		t.Fatal(err)
	}
	if z, _ := zonemgr.ManagedZones(inc); len(z) != 1 {
		t.Fatalf("include: %v", z)
	}
	resp, err = Call(sock, Request{Zone: "example.com", Action: "zone-delete", Apply: true})
	if err == nil || resp == nil || !resp.Refused {
		t.Fatalf("deleting an operator zone must be a flagged refusal: %+v %v", resp, err)
	}
	if _, err := Call(sock, Request{Zone: "new.example.org", Action: "zone-delete", Apply: true}); err != nil {
		t.Fatal(err)
	}
}
